use async_trait::async_trait;
use chrono::{DateTime, Timelike, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::repo::{PageOf, PageRequest, RepoResult};

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

/// True for a run the scheduler created (a nightly scan): schedule slots are whole minutes,
/// while manual, first and operator scans are keyed at the instant they were asked for.
/// shortcut: a scan asked for on an exact minute, to the microsecond, counts as scheduled; give
/// `runs` a trigger column if that ever matters.
pub fn on_schedule_slot(scheduled_at: DateTime<Utc>) -> bool {
    scheduled_at.second() == 0 && scheduled_at.timestamp_subsec_micros() == 0
}

/// A run as read back; runs are written through `opsagent_ledger::Storage`.
#[derive(Debug, Clone, PartialEq)]
pub struct Run {
    pub id: Uuid,
    pub organisation_id: Option<Uuid>,
    pub connection_id: Option<Uuid>,
    pub job_type: String,
    pub status: RunStatus,
    pub scheduled_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub attempts: i32,
    /// The checkpoint's `stats`; null if none.
    pub stats: serde_json::Value,
    pub partial_reason: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct RunFilter {
    pub connection_id: Option<Uuid>,
    pub job_type: Option<String>,
}

/// The read side of runs.
/// Internal billing runs, not shown in an organisation's run history.
pub const HIDDEN_JOB_TYPES: [&str; 6] = [
    "billing_sync",
    "billing_notice",
    "deliver_review_notice",
    "deliver_revoked_notice",
    "deliver_claimed_notice",
    "deliver_scans_failing_notice",
];

#[async_trait]
pub trait RunsRepo: Send + Sync {
    async fn get(&self, organisation_id: Uuid, id: Uuid) -> RepoResult<Option<Run>>;
    /// Newest `scheduled_at` first; `HIDDEN_JOB_TYPES` are never listed.
    async fn list(
        &self,
        organisation_id: Uuid,
        filter: RunFilter,
        page: PageRequest,
    ) -> RepoResult<PageOf<Run>>;
    /// The latest `scheduled_at` of the connection's `full_scan` runs. Any full scan counts
    /// against the manual-scan window: no column tells manual runs from scheduled ones.
    async fn last_manual_scan(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
    ) -> RepoResult<Option<DateTime<Utc>>>;
    /// The connection's unbroken streak of `failed` nightly `full_scan` runs, newest first: how
    /// many, and the `scheduled_at` of the first of them. Nightly runs are those on a schedule
    /// slot (`on_schedule_slot`); one that ended `done` or `partial` ends the streak, and
    /// skipped or unfinished runs are ignored. `None` without a streak.
    async fn failed_scan_streak(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
    ) -> RepoResult<Option<(u64, DateTime<Utc>)>>;
    /// True once the connection has a `full_scan` run that ended `done` or `partial`.
    async fn completed_full_scan(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
    ) -> RepoResult<bool>;
}
