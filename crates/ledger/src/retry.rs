use crate::storage::{LedgerError, Result, Storage};
use chrono::Utc;
use opsagent_core::run::RunStatus;
use std::time::Duration;
use uuid::Uuid;

/// Delay before retry number `attempts + 1`; `None` once retries are exhausted.
pub fn backoff(attempts: u32) -> Option<Duration> {
    let mins = match attempts {
        0 => 1,
        1 => 5,
        2 => 15,
        3 => 60,
        _ => return None,
    };
    Some(Duration::from_secs(mins * 60))
}

/// Parks the run for retry `attempts + 1` (status `queued`, `next_attempt_at` by `backoff`),
/// or fails it with `retries_exhausted`. `true` if a retry was scheduled.
pub async fn retry_or_fail<S: Storage + ?Sized>(
    storage: &S,
    run_id: Uuid,
    attempts: u32,
    fence: u64,
) -> Result<bool> {
    match backoff(attempts) {
        Some(d) => {
            let wait =
                chrono::Duration::from_std(d).map_err(|e| LedgerError::Storage(e.to_string()))?;
            storage
                .schedule_retry(run_id, attempts + 1, Utc::now() + wait)
                .await?;
            Ok(true)
        }
        None => {
            let reason = Some("retries_exhausted".into());
            storage
                .set_status(run_id, fence, RunStatus::Failed, reason)
                .await?;
            Ok(false)
        }
    }
}

/// Final word on a failed job step, while the caller holds the lease at `fence`: a
/// non-retryable `Job` error fails the run with its code; anything else (transient job
/// errors, storage or Redis trouble) retries via `retry_or_fail`. Returns the run's status.
pub async fn settle<S: Storage + ?Sized>(
    storage: &S,
    run_id: Uuid,
    attempts: u32,
    fence: u64,
    e: &LedgerError,
) -> Result<RunStatus> {
    if let LedgerError::Job { code, retry: false } = e {
        tracing::warn!(run = %run_id, code, "run failed");
        storage
            .set_status(run_id, fence, RunStatus::Failed, Some(code.clone()))
            .await?;
        return Ok(RunStatus::Failed);
    }
    match e {
        LedgerError::Job { code, .. } => {
            tracing::warn!(run = %run_id, code, "run step failed, retrying")
        }
        other => tracing::warn!(run = %run_id, error = %other, "run step failed, retrying"),
    }
    Ok(if retry_or_fail(storage, run_id, attempts, fence).await? {
        RunStatus::Queued
    } else {
        RunStatus::Failed
    })
}

/// A storage error ends the run `Failed` with `storage_error`, so a run never stays
/// `running` on one; any other result (`StaleFence` included) passes through. If that write
/// fails too, the original error stands and lease expiry recovers the run.
pub async fn fail_on_storage_error<S: Storage + ?Sized>(
    storage: &S,
    run_id: Uuid,
    fence: u64,
    res: Result<RunStatus>,
) -> Result<RunStatus> {
    let Err(e @ LedgerError::Storage(_)) = res else {
        return res;
    };
    tracing::warn!(run = %run_id, error = %e, "run storage write failed, failing the run");
    match storage.fail_run(run_id, fence, "storage_error").await {
        Ok(()) => Ok(RunStatus::Failed),
        Err(_) => Err(e),
    }
}
