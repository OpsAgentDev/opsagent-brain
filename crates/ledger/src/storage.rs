use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::run::{RunKey, RunStatus};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("stale fence")]
    StaleFence,
    #[error("run not found")]
    NotFound,
    #[error("lease held by another worker")]
    LeaseHeld,
    #[cfg(feature = "test-support")]
    #[error("killed by test harness")]
    Killed,
    #[error("redis: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("storage: {0}")]
    Storage(String),
    /// A job step failed with a stable `code`; `retry`: transient, back off and run again.
    #[error("job step failed: {code}")]
    Job { code: String, retry: bool },
}
pub type Result<T> = std::result::Result<T, LedgerError>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub chunks_done: BTreeSet<String>,
    pub cursor: serde_json::Value,
    pub stats: serde_json::Value,
}

impl Default for Checkpoint {
    fn default() -> Self {
        Self {
            chunks_done: BTreeSet::new(),
            cursor: serde_json::Value::Null,
            stats: serde_json::json!({}),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RunRow {
    pub id: Uuid,
    pub key: RunKey,
    pub status: RunStatus,
    pub checkpoint: Checkpoint,
    pub fence: u64,
    pub attempts: u32,
    pub partial_reason: Option<String>,
}

/// `created` is false when the run key already existed (a duplicate request).
#[derive(Debug, Clone, PartialEq)]
pub struct CreateRunOutcome {
    pub run: RunRow,
    pub created: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EffectState {
    New,
    Started,
    Done(Option<String>),
}

#[async_trait]
pub trait Storage: Send + Sync {
    /// Returns the existing row if the key is a duplicate.
    async fn create_run(&self, key: RunKey) -> Result<CreateRunOutcome>;
    async fn load_run(&self, id: Uuid) -> Result<RunRow>;
    async fn bump_fence(&self, id: Uuid) -> Result<u64>;
    /// `Err(StaleFence)` when `fence` is not the run's current fence.
    async fn write_checkpoint(&self, id: Uuid, fence: u64, cp: &Checkpoint) -> Result<()>;
    async fn set_status(
        &self,
        id: Uuid,
        fence: u64,
        status: RunStatus,
        partial_reason: Option<String>,
    ) -> Result<()>;
    /// Ends the run `Failed` with `reason` at `fence`: the error left nothing to retry.
    async fn fail_run(&self, id: Uuid, fence: u64, reason: &str) -> Result<()> {
        self.set_status(id, fence, RunStatus::Failed, Some(reason.into()))
            .await
    }
    /// Ends a still-`queued` run `Skipped` with `reason` and bumps its fence, so a worker that
    /// already holds the lease gets `StaleFence` on its next write. `false`: not queued.
    async fn skip_run(&self, id: Uuid, reason: &str) -> Result<bool>;
    async fn effect_begin(&self, run_id: Uuid, key: &str) -> Result<EffectState>;
    async fn effect_done(
        &self,
        run_id: Uuid,
        key: &str,
        external_ref: Option<String>,
    ) -> Result<()>;
    /// Outbox marker: sets `next_attempt_at = at` so a run whose enqueue is interrupted is
    /// found again by the due-run dispatcher.
    async fn mark_enqueue_pending(&self, id: Uuid, at: DateTime<Utc>) -> Result<()>;
    /// Clears the marker only if it is still exactly `marker_at`; a retry time written since
    /// (by `schedule_retry`) survives. Returns whether it was cleared.
    async fn clear_enqueue_marker(&self, id: Uuid, marker_at: DateTime<Utc>) -> Result<bool>;
    async fn schedule_retry(&self, id: Uuid, attempts: u32, next_at: DateTime<Utc>) -> Result<()>;
}
