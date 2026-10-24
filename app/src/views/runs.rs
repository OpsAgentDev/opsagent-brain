//! Run wire views, shared by REST controllers and MCP tools.
use chrono::{DateTime, FixedOffset};
use opsagent_core::run;
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::models::enum_str;

#[derive(Serialize, ToSchema)]
pub struct RunSummary {
    pub id: Uuid,
    pub connection_id: Option<Uuid>,
    /// `full_scan`, `verify`, ...
    pub job_type: String,
    /// `queued`, `running`, `done`, `partial`, `failed` or `skipped`.
    pub status: String,
    pub scheduled_at: DateTime<FixedOffset>,
    pub started_at: Option<DateTime<FixedOffset>>,
    pub finished_at: Option<DateTime<FixedOffset>>,
    pub partial_reason: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct Run {
    #[serde(flatten)]
    pub run: RunSummary,
    pub attempts: i32,
    /// Job statistics from the checkpoint (for `full_scan`: score, counts, partial); null if none.
    #[schema(value_type = Option<Object>)]
    pub stats: Option<Value>,
}

pub fn summary(r: run::Run) -> RunSummary {
    RunSummary {
        id: r.id,
        connection_id: r.connection_id,
        job_type: r.job_type,
        status: enum_str(r.status),
        scheduled_at: r.scheduled_at.fixed_offset(),
        started_at: r.started_at.map(|t| t.fixed_offset()),
        finished_at: r.finished_at.map(|t| t.fixed_offset()),
        partial_reason: r.partial_reason,
    }
}

/// The wire view of one run.
pub fn run_view(r: run::Run) -> Run {
    Run {
        attempts: r.attempts,
        stats: Some(r.stats.clone()),
        run: summary(r),
    }
}
