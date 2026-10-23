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

    /// Provider error text can name the customer's role and account (logging.md), so a
    /// `tracing` field must carry the error's code, never its Display. Line-based grep:
    /// flags a Display-formatted `error` field on a line that mentions a connector, provider
    /// or AWS error, and any such field in the connectors crate.
    /// shortcut: misses a provider error bound to a neutral name on another line; upgrade to
    /// a clippy lint if one slips through review.
    #[test]
    fn no_provider_error_is_logged_by_display() {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for e in std::fs::read_dir(dir).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    out.push(p);
                }
            }
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut files = Vec::new();
        walk(&root.join("app/src"), &mut files);
        for c in std::fs::read_dir(root.join("crates")).unwrap().flatten() {
            if c.path().join("src").is_dir() {
                walk(&c.path().join("src"), &mut files);
            }
        }
        let needle = concat!("error", " = %");
        let mut hits = Vec::new();
        for f in &files {
            let in_connectors = f.components().any(|c| c.as_os_str() == "connectors");
            for (i, line) in std::fs::read_to_string(f).unwrap().lines().enumerate() {
                let l = line.to_lowercase();
                let provider = ["connectorerror", "provider", "aws"]
                    .iter()
                    .any(|w| l.contains(w));
                if line.contains(needle) && (provider || in_connectors) {
                    hits.push(format!("{}:{}: {}", f.display(), i + 1, line.trim()));
                }
            }
        }
        assert!(
            hits.is_empty(),
            "log error_code, not the error:\n{}",
            hits.join("\n")
        );
    }
}
