//! `POST /oauth/token` (RFC 6749 section 3.2) and `POST /oauth/revoke` (RFC 7009), both
//! form-encoded.
use axum::{
    extract::{rejection::FormRejection, Form, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde::Deserialize;

use super::OAuthError;
use crate::{actions::oauth::CodeExchange, state::AppState};

#[derive(Debug, Default, Deserialize)]
struct TokenForm {
    grant_type: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    code_verifier: Option<String>,
    resource: Option<String>,
    refresh_token: Option<String>,
}

fn required(v: Option<String>, name: &str) -> Result<String, OAuthError> {
    v.filter(|v| !v.is_empty())
        .ok_or_else(|| OAuthError::invalid_request(format!("{name} is required.")))
}

async fn token(
    State(s): State<AppState>,
    form: Result<Form<TokenForm>, FormRejection>,
) -> Response {
    let Ok(Form(f)) = form else {
        return OAuthError::invalid_request("The body must be form-encoded.").into_response();
    };
    match issue(&s, f).await {
        Ok(body) => (
            [
                (header::CACHE_CONTROL, "no-store"),
                (header::PRAGMA, "no-cache"),
            ],
            Json(body),
        )
            .into_response(),
        Err(e) => e.into_response(),
    }
}

async fn issue(
    s: &AppState,
    f: TokenForm,
) -> Result<crate::actions::oauth::TokenResponse, OAuthError> {
    let now = s.clock.now();
    let oauth = &s.actions.oauth;
    match f.grant_type.as_deref() {
        Some("authorization_code") => {
            let x = CodeExchange {
                code: required(f.code, "code")?,
                client_id: required(f.client_id, "client_id")?,
                redirect_uri: required(f.redirect_uri, "redirect_uri")?,
                code_verifier: required(f.code_verifier, "code_verifier")?,
                resource: f.resource,
            };
            oauth.exchange_code.run(x, now).await
        }
        Some("refresh_token") => {
            let rt = required(f.refresh_token, "refresh_token")?;
            let client_id = required(f.client_id, "client_id")?;
            oauth.refresh_grant.run(&rt, &client_id, now).await
        }
        None => Err(OAuthError::invalid_request("grant_type is required.")),
        Some(_) => Err(OAuthError::unsupported_grant_type(
            "Only authorization_code and refresh_token are supported.",
        )),
    }
}

#[derive(Debug, Deserialize)]
struct RevokeForm {
    token: Option<String>,
}

async fn revoke(
    State(s): State<AppState>,
    form: Result<Form<RevokeForm>, FormRejection>,
) -> Response {
    let Some(token) = form
        .ok()
        .and_then(|Form(f)| f.token)
        .filter(|t| !t.is_empty())
    else {
        return OAuthError::invalid_request("token is required.").into_response();
    };
    match s
        .actions
        .oauth
        .revoke_token
        .run(&token, s.clock.now())
        .await
    {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => e.into_response(),
    }
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/oauth/token", post(token))
        .route("/oauth/revoke", post(revoke))
}
