//! The job queue port: hands a run to the worker for its kind (app-shell.md, jobs).
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::Result;

/// A job type with a worker; the strings are the stored `runs.job_type` values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
