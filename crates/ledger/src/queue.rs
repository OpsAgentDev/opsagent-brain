//! The job queue port: hands a run to the worker for its kind (app-shell.md, jobs).
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::Result;

/// A job type with a worker; the strings are the stored `runs.job_type` values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    Verify,
    FullScan,
    DeliverBriefing,
    DeliverWeekly,
}

impl JobKind {
    pub const ALL: [JobKind; 4] = [
        Self::Verify,
        Self::FullScan,
        Self::DeliverBriefing,
        Self::DeliverWeekly,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verify => "verify",
            Self::FullScan => "full_scan",
            Self::DeliverBriefing => "deliver_briefing",
            Self::DeliverWeekly => "deliver_weekly",
        }
    }

    /// `None` for a job type without a worker.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

/// One run for the worker of `kind`, due at `run_at`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewJob {
    pub kind: JobKind,
    pub run_id: Uuid,
    pub run_at: DateTime<Utc>,
}

#[async_trait]
pub trait Queue: Send + Sync {
    async fn enqueue(&self, job: NewJob) -> Result<()>;
}

/// A dequeued job, locked by the worker that took it. `attempts` counts this one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    pub id: Uuid,
    pub kind: JobKind,
    pub run_id: Uuid,
    pub attempts: i32,
    pub max_attempts: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobFailure {
    Retrying {
        at: DateTime<Utc>,
    },
    /// Attempts exhausted: the job stays locked with its error and the run is failed.
    Dead,
    /// The job is no longer this attempt's (another worker took it over): nothing was written.
    LockLost,
}

/// The worker side of the queue.
#[async_trait]
pub trait JobSource: Send + Sync {
    /// Locks the oldest due job of one of `kinds`; a lock older than `lock_max_age` counts as free.
    async fn dequeue(
        &self,
        worker_id: &str,
        kinds: &[JobKind],
        lock_max_age: Duration,
    ) -> Result<Option<Job>>;
    /// The job succeeded: deletes it. `false`: the lock was lost and nothing was deleted.
    /// `complete` and `fail` act only while the row is still locked at `job.attempts`.
    async fn complete(&self, job: &Job) -> Result<bool>;
    /// Unlocks for a retry at `now + retry::backoff(retries so far)`, or `Dead`.
    async fn fail(&self, job: &Job, error: &str, now: DateTime<Utc>) -> Result<JobFailure>;
    /// Shutdown: unlocks this worker's jobs without counting the interrupted attempt, due once
    /// the dropped handlers' ledger leases have lapsed.
    async fn release_mine(&self, worker_id: &str) -> Result<u64>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_kind_round_trips_every_stored_string() {
        let stored = ["verify", "full_scan", "deliver_briefing", "deliver_weekly"];
        assert_eq!(JobKind::ALL.map(JobKind::as_str), stored);
        for (k, s) in JobKind::ALL.into_iter().zip(stored) {
            assert_eq!(JobKind::parse(s), Some(k));
            assert_eq!(serde_json::to_value(k).unwrap(), s);
        }
        assert_eq!(JobKind::parse("no_worker"), None);
    }
}
