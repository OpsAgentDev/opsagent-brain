//! `AppError`: the one error type of every action, and its single mapping to problem details.
use axum::http::StatusCode;
use opsagent_core::repo::RepoError;
use opsagent_ledger::LedgerError;

use crate::api_error::ApiError;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("unauthenticated")]
    Unauthenticated,
    #[error("forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("invalid: {0}")]
    Invalid(String),
    #[error("rate limited")]
    RateLimited {
        detail: String,
        retry_after_secs: u64,
    },
    #[error("gone: {0}")]
    Gone(&'static str),
    /// A refusal with its own status and code (what handlers built with `ApiError::new`).
    #[error("{code}")]
    Refused {
        status: StatusCode,
        code: &'static str,
        detail: String,
    },
    #[error(transparent)]
    Repo(#[from] RepoError),
    #[error(transparent)]
    Ledger(#[from] LedgerError),
    #[error("internal: {0}")]
    Internal(String),
}

pub type AppResult<T> = Result<T, AppError>;

impl From<AppError> for ApiError {
    fn from(e: AppError) -> Self {
        match e {
            AppError::Unauthenticated => Self::unauthenticated(),
            AppError::Forbidden => Self::forbidden(),
            AppError::NotFound | AppError::Repo(RepoError::NotFound) => Self::not_found(),
            AppError::Invalid(detail) => Self::invalid(detail),
            AppError::RateLimited {
                detail,
                retry_after_secs,
            } => Self::rate_limited(detail, retry_after_secs),
            AppError::Gone(code) => Self::gone(code),
            AppError::Refused {
                status,
                code,
                detail,
            } => Self::new(status, code, detail),
            AppError::Repo(RepoError::Conflict(_)) => Self::new(
                StatusCode::CONFLICT,
                "conflict",
                "The request conflicts with the current state.",
            ),
            e @ (AppError::Repo(_) | AppError::Ledger(_) | AppError::Internal(_)) => {
                Self::internal(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::{http::header::RETRY_AFTER, response::IntoResponse};

    use super::*;

    #[tokio::test]
    async fn app_error_maps_to_same_problem_codes() {
        let refused = |status, code| AppError::Refused {
            status,
            code,
            detail: "x".into(),
        };
        let cases: Vec<(AppError, u16, &str, Option<&str>)> = vec![
            (AppError::Unauthenticated, 401, "unauthenticated", None),
            (AppError::Forbidden, 403, "forbidden", None),
            (AppError::NotFound, 404, "not_found", None),
            (AppError::Invalid("bad".into()), 422, "validation", None),
            (
                AppError::RateLimited {
                    detail: "slow".into(),
                    retry_after_secs: 60,
                },
                429,
                "rate_limited",
                Some("60"),
            ),
            (AppError::Gone("link_invalid"), 410, "link_invalid", None),
            // The auth routes' own refusals keep their status and code.
            (
                refused(StatusCode::FORBIDDEN, "bad_origin"),
                403,
                "bad_origin",
                None,
            ),
            (
                refused(StatusCode::BAD_REQUEST, "oauth_state"),
                400,
                "oauth_state",
                None,
            ),
            (
                refused(StatusCode::BAD_GATEWAY, "oauth_exchange"),
                502,
                "oauth_exchange",
                None,
            ),
            (
                refused(StatusCode::SERVICE_UNAVAILABLE, "github_not_configured"),
                503,
                "github_not_configured",
                None,
            ),
            (AppError::Repo(RepoError::NotFound), 404, "not_found", None),
            (
                AppError::Repo(RepoError::Conflict("slug")),
                409,
                "conflict",
                None,
            ),
            (
                AppError::Repo(RepoError::Storage("db".into())),
                500,
                "internal",
                None,
            ),
            (
                AppError::Ledger(LedgerError::Storage("db".into())),
                500,
                "internal",
                None,
            ),
            (AppError::Internal("boom".into()), 500, "internal", None),
        ];
        for (e, status, code, retry_after) in cases {
            let res = ApiError::from(e).into_response();
            assert_eq!(res.status().as_u16(), status, "{code}");
            let got = res
                .headers()
                .get(RETRY_AFTER)
                .map(|v| v.to_str().unwrap().to_owned());
            assert_eq!(got.as_deref(), retry_after, "{code}");
            let body = axum::body::to_bytes(res.into_body(), usize::MAX)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["code"], code);
        }
    }
}
