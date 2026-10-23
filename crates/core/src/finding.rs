//! Findings: the dedup key, drafts checks emit, stored findings and their repository.
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::repo::{PageOf, PageRequest, RepoResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn weight(self) -> f32 {
        match self {
            Self::Critical => 10.0,
            Self::High => 5.0,
            Self::Medium => 2.0,
            Self::Low => 0.5,
            Self::Info => 0.0,
        }
    }
}

/// Dedup identity of a finding across runs (PRD 7.4).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FindingKey {
    pub connection_id: Uuid,
    pub check_id: String,
    pub resource_identity: String,
    pub variant: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub source: String,
    pub excerpt: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindingDraft {
    pub key: FindingKey,
    pub severity: Severity,
    pub title: String,
    pub summary: String,
    pub next_step: String,
    pub cost_monthly_usd: Option<f64>,
    pub evidence: Vec<Evidence>,
}

/// One draft per key (checks may emit a key twice): highest severity wins, evidence merges.
pub fn dedupe(drafts: &[FindingDraft]) -> Vec<FindingDraft> {
    let mut out: Vec<FindingDraft> = Vec::with_capacity(drafts.len());
    for d in drafts {
        match out.iter_mut().find(|o| o.key == d.key) {
            Some(o) => {
                let mut evidence = std::mem::take(&mut o.evidence);
                evidence.extend(d.evidence.iter().cloned());
                if d.severity.weight() > o.severity.weight() {
                    *o = d.clone();
                }
                o.evidence = evidence;
            }
            None => out.push(d.clone()),
        }
    }
    out
}

/// A stored finding. `status` is `open`, `resolved`, `accepted`, `snoozed` or `flapping`.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub id: Uuid,
    pub organisation_id: Uuid,
    pub connection_id: Uuid,
    pub key: FindingKey,
    pub severity: Severity,
    pub status: String,
    pub title: String,
    pub accepted_reason: Option<String>,
    pub accepted_until: Option<DateTime<Utc>>,
    pub snoozed_until: Option<DateTime<Utc>>,
    pub first_seen_run_id: Option<Uuid>,
    pub last_seen_run_id: Option<Uuid>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default)]
pub struct FindingFilter {
    pub connection_id: Option<Uuid>,
    pub status: Option<String>,
    pub severity: Option<Severity>,
    pub check_id: Option<String>,
}

/// One lifecycle or customer event; `run_id` is `None` for customer actions.
#[derive(Debug, Clone, PartialEq)]
pub struct FindingEvent {
    pub finding_id: Uuid,
    pub kind: String,
    pub run_id: Option<Uuid>,
    pub from_severity: Option<Severity>,
    pub to_severity: Option<Severity>,
    pub at: DateTime<Utc>,
}

/// A customer status change, applied only while the finding is still `from_status`.
#[derive(Debug, Clone)]
pub struct StatusChange {
    pub from_status: String,
    pub status: String,
    pub accepted_reason: Option<String>,
    pub accepted_until: Option<DateTime<Utc>>,
    pub snoozed_until: Option<DateTime<Utc>>,
    pub event: FindingEvent,
}

/// Open findings of one check at one severity.
#[derive(Debug, Clone, PartialEq)]
pub struct PostureRow {
    pub check_id: String,
    pub severity: Severity,
    pub open: u64,
}

#[async_trait]
pub trait FindingsRepo: Send + Sync {
    async fn get(&self, organisation_id: Uuid, id: Uuid) -> RepoResult<Option<Finding>>;
    async fn list(
        &self,
        organisation_id: Uuid,
        filter: FindingFilter,
        page: PageRequest,
    ) -> RepoResult<PageOf<Finding>>;
    /// Newest first.
    async fn events(
        &self,
        organisation_id: Uuid,
        finding_id: Uuid,
    ) -> RepoResult<Vec<FindingEvent>>;
    /// Unexpired evidence, newest first.
    async fn evidence(&self, organisation_id: Uuid, finding_id: Uuid) -> RepoResult<Vec<Evidence>>;
    /// `NotFound` for an unknown id, `Conflict("finding_state_changed")` when the status moved.
    async fn change_status(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        change: StatusChange,
    ) -> RepoResult<Finding>;
    /// Upsert every draft seen in this run, deduped by key (`dedupe`), with the lifecycle and
    /// stability counters of PRD 7.4. The in-memory fake implements open, seen, reopen and
    /// expiry only; flapping, escalation and stability counters are Pg-only, so tests of them
    /// run on Pg (`workers/full_scan.rs`).
    async fn upsert_seen(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
        run_id: Uuid,
        drafts: &[FindingDraft],
        now: DateTime<Utc>,
    ) -> RepoResult<()>;
    /// Resolve open or flapping findings not seen in `run_id`, except those of
    /// `except_check_ids` (checks whose capability was partial); returns how many.
    async fn resolve_unseen(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
        run_id: Uuid,
        except_check_ids: &[String],
        now: DateTime<Utc>,
    ) -> RepoResult<u64>;
    async fn posture_rows(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
    ) -> RepoResult<Vec<PostureRow>>;
}
