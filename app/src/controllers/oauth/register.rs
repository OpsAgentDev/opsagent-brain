//! `POST /oauth/register` (RFC 7591).
use axum::{
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde_json::json;

use super::OAuthError;
use crate::{actions::oauth::RegistrationRequest, adapters::client_ip::ClientIp, state::AppState};

async fn register(State(s): State<AppState>, ip: ClientIp, body: Bytes) -> Response {
    let req: RegistrationRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => {
            return OAuthError::invalid_client_metadata("The body is not valid registration JSON.")
                .into_response()
        }
    };
    match s.actions.oauth.register_client.run(req, ip.0).await {
        Ok(c) => (
            StatusCode::CREATED,
            Json(json!({
                "client_id": c.client_id,
                "client_name": c.name,
                "redirect_uris": c.redirect_uris,
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            })),
        )
            .into_response(),
        Err(e) => e.into_response(),
    }
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/oauth/register", post(register))
}
