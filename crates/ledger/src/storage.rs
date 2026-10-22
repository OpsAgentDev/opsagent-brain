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
    #[error("killed by test harness")]
    Killed,
    #[error("redis: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("storage: {0}")]
    Storage(String),
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

#[derive(Debug, Clone, PartialEq)]
pub enum EffectState {
    New,
    Started,
    Done(Option<String>),
}

#[async_trait]
pub trait Storage: Send + Sync {
    /// Returns the existing row if the key is a duplicate.
    async fn create_run(&self, key: RunKey) -> Result<RunRow>;
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
    async fn effect_begin(&self, run_id: Uuid, key: &str) -> Result<EffectState>;
    async fn effect_done(
        &self,
        run_id: Uuid,
        key: &str,
        external_ref: Option<String>,
    ) -> Result<()>;
    async fn schedule_retry(&self, id: Uuid, attempts: u32, next_at: DateTime<Utc>) -> Result<()>;
}
