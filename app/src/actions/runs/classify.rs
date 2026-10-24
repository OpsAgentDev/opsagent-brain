//! Connector errors as job outcomes: stable codes, and which ones a retry can help.
use opsagent_connectors::{aws::client::is_access_denied, ConnectorError};
use opsagent_ledger::LedgerError;

pub(crate) type LResult<T> = std::result::Result<T, LedgerError>;

pub(crate) fn lerr(e: impl std::fmt::Display) -> LedgerError {
    LedgerError::Storage(e.to_string())
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

/// Stable error code (never the message) and whether a retry can help: throttling, 5xx and
/// network (an `Api` error without a code) only.
pub(crate) fn classify(e: &ConnectorError) -> (String, bool) {
    let transient = match e {
        ConnectorError::Api { code: Some(c), .. } => TRANSIENT_CODES.contains(&c.as_str()),
        ConnectorError::Api { code: None, .. } => true,
        _ => false,
    };
    (e.code().to_owned(), transient)
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
