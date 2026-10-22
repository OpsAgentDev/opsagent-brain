use axum::{
    extract::{FromRequest, Request},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use serde::de::DeserializeOwned;
use serde_json::json;
use uuid::Uuid;

/// RFC 9457 problem details; the single error type for every API handler.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    detail: String,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status,
            code,
            detail: detail.into(),
        }
    }
    pub fn unauthenticated() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "Sign in required.",
        )
    }
    pub fn forbidden() -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", "Owner role required.")
    }
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", "No such resource.")
    }
    pub fn invalid(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid_request", detail)
    }
    pub fn gone(code: &'static str) -> Self {
        Self::new(
            StatusCode::GONE,
            code,
            "This link is invalid, expired or already used.",
        )
    }
    pub fn internal(e: impl std::fmt::Display) -> Self {
        tracing::error!(error = %e, "internal error");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "Internal error.",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = json!({
            "type": format!("https://opsagent.dev/problems/{}", self.code),
            "title": self.status.canonical_reason().unwrap_or("Error"),
            "status": self.status.as_u16(),
            "detail": self.detail,
            "instance": format!("urn:uuid:{}", Uuid::new_v4()),
            "code": self.code,
        });
        (
            self.status,
            [(header::CONTENT_TYPE, "application/problem+json")],
            body.to_string(),
        )
            .into_response()
    }
}

macro_rules! internal_from {
    ($($t:ty),*) => {$(impl From<$t> for ApiError {
        fn from(e: $t) -> Self { Self::internal(e) }
    })*};
}
internal_from!(
    sea_orm::DbErr,
    loco_rs::Error,
    tower_sessions::session::Error,
    opsagent_secrets::SecretsError
);

/// `Json` extractor whose rejection is a problem-details body.
pub struct ApiJson<T>(pub T);

impl<T: DeserializeOwned, S: Send + Sync> FromRequest<S> for ApiJson<T> {
    type Rejection = ApiError;
    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        axum::Json::<T>::from_request(req, state)
            .await
            .map(|j| Self(j.0))
            .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, "invalid_body", e.body_text()))
    }
}
