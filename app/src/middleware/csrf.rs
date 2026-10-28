use axum::{
    extract::{Request, State},
    http::Method,
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tower_sessions::Session;
use uuid::Uuid;

use super::session::USER_KEY;
use crate::{api_error::ApiError, state::AppState};

fn mac(secret: &str, session_id: &str) -> Hmac<Sha256> {
    let mut m = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac accepts any key");
    m.update(session_id.as_bytes());
    m
}

pub fn token(secret: &str, session_id: &str) -> String {
    B64.encode(mac(secret, session_id).finalize().into_bytes())
}

/// Mutating requests on a signed-in session must carry the matching `X-CSRF-Token`.
/// Anonymous requests (magic-link request, GitHub start) have no session to ride on.
/// Safe methods are exempt, which covers health and the OAuth callback (both GET).
pub async fn guard(State(app): State<AppState>, req: Request, next: Next) -> Response {
    let safe = matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    // Anonymous by design: redeem, verify and passkey login have their own Origin check; recipient
    // confirm and unsubscribe are authorised by their single-use token alone.
    let path = req.uri().path();
    let exempt = path == "/v1/auth/magic-link/redeem"
        || path == "/v1/auth/magic-link/verify"
        || path == "/v1/auth/passkeys/login/start"
        || path == "/v1/auth/passkeys/login/finish"
        || path == "/v1/recipients/confirm"
        || path.starts_with("/v1/unsubscribe/");
    if !safe && !exempt {
        if let Some(session) = req.extensions().get::<Session>() {
            let signed_in = matches!(session.get::<Uuid>(USER_KEY).await, Ok(Some(_)));
            if signed_in {
                let secret = &app.config.session_secret;
                let sid = session.id().map(|i| i.to_string()).unwrap_or_default();
                let ok = req
                    .headers()
                    .get("x-csrf-token")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| B64.decode(v).ok())
                    .is_some_and(|given| mac(secret, &sid).verify_slice(&given).is_ok());
                if !ok {
                    return ApiError::new(
                        axum::http::StatusCode::FORBIDDEN,
                        "csrf",
                        "Missing or invalid X-CSRF-Token.",
                    )
                    .into_response();
                }
            }
        }
    }
    next.run(req).await
}
