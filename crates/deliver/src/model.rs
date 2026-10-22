//! Snapshots built by the workers, and the documents built from them.
use chrono::{DateTime, NaiveDate, Utc};
use opsagent_core::connection::ConnectionStatus;
use opsagent_core::finding::{FindingKey, Severity};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Mirrors `finding_events.kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Opened,
    Seen,
    Reopened,
    Flapping,
    Escalated,
    Deescalated,
    Resolved,
}

/// Mirrors `findings.status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Open,
    Flapping,
    Accepted,
    Snoozed,
    Resolved,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindingSnapshot {
    pub id: Uuid,
    pub key: FindingKey,
    pub severity: Severity,
    pub status: FindingStatus,
    pub title: String,
    pub cost_monthly_usd: Option<f64>,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    /// Events written for this finding since the window start, oldest first.
    pub events_since: Vec<EventKind>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeverityCounts {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectionSnapshot {
    pub id: Uuid,
    pub display_name: String,
    pub status: ConnectionStatus,
    pub status_reason: Option<String>,
    pub posture_score: Option<f64>,
    pub prev_posture_score: Option<f64>,
    /// Open findings now.
    pub counts_by_severity: SeverityCounts,
    pub first_scan_at: Option<DateTime<Utc>>,
    pub last_scan_at: Option<DateTime<Utc>>,
    /// The last scan ended partial.
    pub partial: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpendSnapshot {
    pub this_week_usd: f64,
    pub last_week_usd: f64,
    /// (day, amount, baseline) in USD.
    pub anomalies: Vec<(NaiveDate, f64, f64)>,
}

/// Weekly inputs that do not come from findings or spend.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct WeeklyExtras {
    pub last_restore_test_on: Option<NaiveDate>,
    pub untagged_spend_pct: Option<f64>,
    /// Write candidates the agent would have run (v2 preview), one line each.
    pub would_have_done: Vec<String>,
}

/// A briefing or weekly line: title only, never evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Item {
    pub id: Uuid,
    pub severity: Severity,
    pub title: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Health {
    pub status: ConnectionStatus,
    pub reason: Option<String>,
    pub partial: bool,
    /// No scan in the last 48 hours.
    pub stale: bool,
}

/// Section totals before the 10-item cap, plus open findings now.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DailyCounts {
    pub new_critical_high: usize,
    pub escalated: usize,
    pub resolved_critical: usize,
    pub open: SeverityCounts,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Briefing {
    FirstScan {
        counts: SeverityCounts,
        link: String,
    },
    Daily {
        new_critical_high: Vec<Item>,
        escalated: Vec<Item>,
        resolved_critical: Vec<Item>,
        health: Option<Health>,
        counts: DailyCounts,
        link: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpendSection {
    pub this_week_usd: f64,
    pub last_week_usd: f64,
    pub delta_usd: f64,
    pub anomalies: Vec<(NaiveDate, f64, f64)>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CostAction {
    pub id: Uuid,
    pub title: String,
    pub savings_monthly_usd: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PostureDelta {
    pub score: Option<f64>,
    pub delta: Option<f64>,
}

/// Check 02 findings: open now, opened and resolved this week.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IamDelta {
    pub open: usize,
    pub opened: usize,
    pub resolved: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BackupStatus {
    /// Open check 04 findings.
    pub open_issues: usize,
    pub last_restore_test_on: Option<NaiveDate>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Weekly {
    pub connection_name: String,
    pub first_week: bool,
    /// `None`: spend is not collected yet (rendered "not tracked yet", never $0.00).
    pub spend: Option<SpendSection>,
    pub recommended_cost_action: Option<CostAction>,
    pub posture: PostureDelta,
    pub iam: IamDelta,
    pub backups: BackupStatus,
    /// Open check 05 findings, most severe first.
    pub certificates: Vec<Item>,
    pub untagged_spend_pct: Option<f64>,
    /// Open critical and high findings, most severe first, at most 10.
    pub awaiting_decision: Vec<Item>,
    pub would_have_done: Vec<String>,
    pub inventory: SeverityCounts,
    pub link: String,
    pub need_a_human_url: String,
}

impl Item {
    pub fn of(f: &FindingSnapshot) -> Self {
        Self {
            id: f.id,
            severity: f.severity,
            title: f.title.clone(),
        }
    }
}

pub fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

/// Most severe first; stable otherwise.
pub fn by_severity(items: &mut [Item]) {
    items.sort_by(|a, b| b.severity.weight().total_cmp(&a.severity.weight()));
}

pub fn connection_link(link_base: &str, id: Uuid) -> String {
    format!("{}/connections/{id}", link_base.trim_end_matches('/'))
}
