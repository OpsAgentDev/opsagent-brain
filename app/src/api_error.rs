use axum::{
    extract::{FromRequest, FromRequestParts, Query, Request},
    http::{header, request::Parts, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{de::DeserializeOwned, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// RFC 9457 problem details; the single error type for every API handler.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    detail: String,
    retry_after_secs: Option<u64>,
}

/// The wire shape of every error (`application/problem+json`).
#[derive(Serialize, ToSchema)]
pub struct Problem {
    #[serde(rename = "type")]
    pub kind: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    /// Unique per response.
    pub instance: String,
    /// Stable machine-readable code, e.g. `not_found`, `validation`, `rate_limited`, `csrf`.
    pub code: String,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status,
            code,
            detail: detail.into(),
            retry_after_secs: None,
        }
    }
    /// The stable machine-readable code.
    pub fn code(&self) -> &'static str {
        self.code
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
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, "validation", detail)
    }
    /// 429 with `Retry-After`.
    pub fn rate_limited(detail: impl Into<String>, retry_after_secs: u64) -> Self {
        Self {
            retry_after_secs: Some(retry_after_secs),
            ..Self::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", detail)
        }
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
        let body = Problem {
            kind: format!("https://opsagent.dev/problems/{}", self.code),
            title: self.status.canonical_reason().unwrap_or("Error").into(),
            status: self.status.as_u16(),
            detail: self.detail,
            instance: format!("urn:uuid:{}", Uuid::new_v4()),
            code: self.code.into(),
        };
        let body = serde_json::to_string(&body).unwrap_or_default();
        let mut res = (
            self.status,
            [(header::CONTENT_TYPE, "application/problem+json")],
            body,
        )
            .into_response();
        if let Some(s) = self.retry_after_secs {
            res.headers_mut().insert(header::RETRY_AFTER, s.into());
        }
        res
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
    opsagent_secrets::SecretsError,
    opsagent_ledger::LedgerError
);

impl From<opsagent_core::repo::RepoError> for ApiError {
    fn from(e: opsagent_core::repo::RepoError) -> Self {
        match e {
            opsagent_core::repo::RepoError::NotFound => Self::not_found(),
            e => Self::internal(e),
        }
    }
}

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

/// `Query` extractor whose rejection is a 422 `validation` problem.
pub struct ApiQuery<T>(pub T);

impl<T: DeserializeOwned, S: Send + Sync> FromRequestParts<S> for ApiQuery<T> {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        Query::<T>::from_request_parts(parts, state)
            .await
            .map(|q| Self(q.0))
            .map_err(|e| ApiError::invalid(e.body_text()))
    }
}
