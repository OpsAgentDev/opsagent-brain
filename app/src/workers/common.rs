//! Shared by every worker: error mapping, the Redis client, ledger-owned retries and the
//! connector error classification.
use chrono::Utc;
use loco_rs::{app::AppContext, config::QueueConfig, Error, Result};
use opsagent_connectors::{Connector, ConnectorError};
use opsagent_core::run::RunStatus;
use opsagent_ledger::{redis, retry::backoff, LedgerError, RunRow, Storage};
use sea_orm::EntityTrait;
use uuid::Uuid;

use crate::{
    app::registry,
    models::{_entities::connections, ledger_storage::PgStorage},
};

pub(crate) type LResult<T> = std::result::Result<T, LedgerError>;

pub(crate) fn err(e: impl std::fmt::Display) -> Error {
    Error::string(&e.to_string())
}

pub(crate) fn lerr(e: impl std::fmt::Display) -> LedgerError {
    LedgerError::Storage(e.to_string())
}

pub(crate) fn redis_client(ctx: &AppContext) -> Result<redis::Client> {
    let Some(QueueConfig::Redis(cfg)) = &ctx.config.queue else {
        return Err(err("workers need the redis queue config"));
    };
    redis::Client::open(cfg.uri.as_str()).map_err(err)
}

/// The registry's connector for the provider of run `run_id`'s connection.
pub(crate) async fn connector_for(ctx: &AppContext, run_id: Uuid) -> Result<Box<dyn Connector>> {
    let run = PgStorage::new(ctx.db.clone())
        .load_run(run_id)
        .await
        .map_err(err)?;
    let id = run
        .key
        .connection_id
        .ok_or_else(|| err("run has no connection"))?;
    let c = connections::Entity::find_by_id(id)
        .one(&ctx.db)
        .await?
        .ok_or_else(|| err("connection not found"))?;
    registry(ctx)?.connector(&c.provider).map_err(err)
}

/// Ledger-owned retry: 1, 5, 15, 60 minutes. `false` (run marked failed) once exhausted.
pub(crate) async fn retry<S: Storage + ?Sized>(
    storage: &S,
    run: &RunRow,
    fence: u64,
) -> LResult<bool> {
    match backoff(run.attempts) {
        Some(d) => {
            let at = Utc::now() + chrono::Duration::from_std(d).map_err(lerr)?;
            storage.schedule_retry(run.id, run.attempts + 1, at).await?;
            Ok(true)
        }
        None => {
            let reason = Some("retries_exhausted".into());
            storage
                .set_status(run.id, fence, RunStatus::Failed, reason)
                .await?;
            Ok(false)
        }
    }
}

/// AWS error codes worth retrying: throttling and server-side faults. Any other code is a
/// deterministic 4xx (ValidationError, NoSuchEntity, MalformedPolicyDocument, ...).
const TRANSIENT_CODES: &[&str] = &[
    "Throttling",
    "ThrottlingException",
    "ThrottledException",
    "RequestThrottled",
    "RequestThrottledException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
    "PriorRequestNotComplete",
    "RequestTimeout",
    "RequestTimeoutException",
    "ServiceUnavailable",
    "ServiceUnavailableException",
    "InternalError",
    "InternalFailure",
    "InternalServerError",
    "InternalServiceError",
];

/// Stable error code (never the message) and whether a retry can help.
pub(crate) fn classify(e: &ConnectorError) -> (String, bool) {
    use ConnectorError as C;
    match e {
        C::Api {
            code: Some(code), ..
        } => (code.clone(), TRANSIENT_CODES.contains(&code.as_str())),
        // No code: the request never got an answer (timeout, connection reset).
        C::Api { code: None, .. } => ("network".into(), true),
        C::Provider(_) => ("provider_error".into(), false),
        C::NotFound => ("not_found".into(), false),
        C::InvalidCredentials(_) => ("invalid_credentials".into(), false),
        C::Auth(_) => ("auth".into(), false),
        C::Template(_) => ("template".into(), false),
        C::Fixture(_) => ("fixture".into(), false),
        C::Unknown(_) => ("unknown_connector".into(), false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_retries_only_throttling_5xx_and_network() {
        let api = |c: Option<&str>| ConnectorError::Api {
            code: c.map(Into::into),
            message: "m".into(),
        };
        for c in ["Throttling", "ServiceUnavailable", "InternalFailure"] {
            assert_eq!(classify(&api(Some(c))), (c.to_owned(), true));
        }
        for c in [
            "ValidationError",
            "NoSuchEntity",
            "MalformedPolicyDocument",
            "InvalidInput",
        ] {
            assert_eq!(classify(&api(Some(c))), (c.to_owned(), false));
        }
        assert_eq!(classify(&api(None)), ("network".into(), true));
        assert_eq!(
            classify(&ConnectorError::NotFound),
            ("not_found".into(), false)
        );
    }
}
