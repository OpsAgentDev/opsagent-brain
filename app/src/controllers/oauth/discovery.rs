//! RFC 9728 protected-resource and RFC 8414 authorization-server metadata.
use axum::{extract::State, routing::get, Json, Router};
use opsagent_core::oauth::SCOPE;
use serde_json::{json, Value};

use crate::state::AppState;

async fn resource(State(s): State<AppState>) -> Json<Value> {
    Json(json!({
        "resource": s.oauth_urls.resource,
        "authorization_servers": [s.oauth_urls.issuer],
        "scopes_supported": [SCOPE],
        "bearer_methods_supported": ["header"],
    }))
}

async fn authorization_server(State(s): State<AppState>) -> Json<Value> {
    let issuer = &s.oauth_urls.issuer;
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth/authorize"),
        "token_endpoint": format!("{issuer}/oauth/token"),
        "registration_endpoint": format!("{issuer}/oauth/register"),
        "revocation_endpoint": format!("{issuer}/oauth/revoke"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": [SCOPE],
        "client_id_metadata_document_supported": true,
        "authorization_response_iss_parameter_supported": true,
    }))
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/.well-known/oauth-protected-resource/mcp", get(resource))
        .route("/.well-known/oauth-protected-resource", get(resource))
        .route(
            "/.well-known/oauth-authorization-server",
            get(authorization_server),
        )
}
