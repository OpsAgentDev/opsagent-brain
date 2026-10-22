use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Queued,
    Running,
    Partial,
    Done,
    Failed,
    Skipped,
}

/// Unique run identity; makes scheduling idempotent per (scope, job, time).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RunKey {
    pub organisation_id: Option<Uuid>,
    pub connection_id: Option<Uuid>,
    pub job_type: String,
    pub scheduled_at: DateTime<Utc>,
}
