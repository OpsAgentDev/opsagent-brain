//! RFC 6749 error bodies for OAuth endpoints (never problem+json).
use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthError {
    pub status: StatusCode,
    pub error: &'static str,
    pub description: String,
}

impl OAuthError {
    fn new(status: StatusCode, error: &'static str, description: impl Into<String>) -> Self {
        Self {
            status,
            error,
            description: description.into(),
        }
    }

    pub fn invalid_request(d: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", d)
    }

    pub fn invalid_client(d: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "invalid_client", d)
    }

    pub fn invalid_grant(d: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_grant", d)
    }

    pub fn unsupported_grant_type(d: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "unsupported_grant_type", d)
    }

    pub fn invalid_client_metadata(d: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_client_metadata", d)
    }

    pub fn invalid_redirect_uri(d: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_redirect_uri", d)
    }

    pub fn slow_down(d: impl Into<String>) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, "slow_down", d)
    }

    /// The cause is logged by the caller; the client sees nothing of it.
    pub fn server_error() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "The server could not complete the request.",
        )
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let body = json!({"error": self.error, "error_description": self.description});
        let mut res = (self.status, Json(body)).into_response();
        // RFC 6749 section 5.1: error bodies must not be cached.
        res.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        res
    }
}
