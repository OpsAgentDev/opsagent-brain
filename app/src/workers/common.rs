//! Shared by every worker: error mapping, the Redis client and the connector error
//! classification. Retries are the ledger's (`opsagent_ledger::retry`).
use loco_rs::{app::AppContext, config::QueueConfig, Error, Result};
use opsagent_connectors::{aws::client::is_access_denied, ConnectorError};
use opsagent_ledger::{redis, LedgerError};

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

/// A connector error as a job step failure: its stable code, retryable if transient.
pub(crate) fn job_err(e: &ConnectorError) -> LedgerError {
    let (code, retry) = classify(e);
    LedgerError::Job { code, retry }
}

/// The customer's role no longer lets us in (stack deleted, trust changed).
pub(crate) fn revoked(e: &ConnectorError) -> bool {
    matches!(e, ConnectorError::Auth(_)) || is_access_denied(e)
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
