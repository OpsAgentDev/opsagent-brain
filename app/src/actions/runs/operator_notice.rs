//! The nightly operator notice, mailed to the contact address once every night: new
//! sign-ups and waitlist entries over the last 24 hours, then dead jobs and failed runs,
//! the mail sent on a day near the mail plan's daily stop, the day's counted failures
//! (`day_counts`), and scans skipped for billing (a read-only organisation). On a Monday (UTC) the mail opens with the week's marketing numbers. The subject says whether anything failed.
//! Counts and job kinds only: no customer data.
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use opsagent_core::run::RunStatus;
use opsagent_ledger::{
    effects::with_effect, redis, ChunkOutcome, LedgerError, RunChunkedOptions, RunRow,
};
use serde_json::json;
use uuid::Uuid;

use super::{
    classify::{lerr, LResult},
    one_chunk_run,
    week_counts::{is_monday, WeekCounts},
};
use crate::{
    actions::{ai::CreditTally, day_counts, uow::UnitOfWork},
    error::AppResult,
    mailers::{branded, counting::reportable_days, Mail, Mailer},
};

/// (job kind, count), by kind.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Failures {
    pub dead_jobs: Vec<(String, i64)>,
    pub failed_runs: Vec<(String, i64)>,
    /// Runs skipped because the organisation has no plan (`partial_reason = billing`).
    pub skipped_billing: Vec<(String, i64)>,
}

impl Failures {
    fn is_empty(&self) -> bool {
        self.dead_jobs.is_empty() && self.failed_runs.is_empty()
    }
}

/// New accounts over the window, across all organisations.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Signups {
    pub users: i64,
    pub organisations: i64,
    pub waitlist: i64,
}

/// Reads the night's counts across all organisations; aggregates only.
#[async_trait]
pub trait FailureCounts: Send + Sync {
    async fn since(&self, since: DateTime<Utc>) -> AppResult<Failures>;
    async fn signups_since(&self, since: DateTime<Utc>) -> AppResult<Signups>;
    /// The 7 days ending at `until`.
    async fn week_until(&self, until: DateTime<Utc>) -> AppResult<WeekCounts>;
}

#[derive(Clone)]
pub struct OperatorNotice {
    failures: Arc<dyn FailureCounts>,
    /// The day counters `CountingMailer` and `DayCounter` write.
    mail_counts: Arc<dyn CreditTally>,
    uow: Arc<dyn UnitOfWork>,
    redis: redis::Client,
    mailer: Arc<dyn Mailer>,
    contact_to: String,
}

impl OperatorNotice {
    pub fn new(
        failures: Arc<dyn FailureCounts>,
        mail_counts: Arc<dyn CreditTally>,
        uow: Arc<dyn UnitOfWork>,
        redis: redis::Client,
        mailer: Arc<dyn Mailer>,
        contact_to: String,
    ) -> Self {
        Self {
            failures,
            mail_counts,
            uow,
            redis,
            mailer,
            contact_to,
        }
    }

    /// Runs (or resumes) the night's run `run_id`; its schedule slot is the once-per-night.
    pub async fn run(&self, run_id: Uuid, opts: RunChunkedOptions) -> LResult<RunStatus> {
        let send = |run: RunRow| async move { self.send(&run).await };
        one_chunk_run(&*self.uow, &self.redis, run_id, opts, send).await
    }

    async fn send(&self, run: &RunRow) -> LResult<ChunkOutcome> {
        let since = run.key.scheduled_at - Duration::hours(24);
        let found = self.failures.since(since).await.map_err(lerr)?;
        let signups = self.failures.signups_since(since).await.map_err(lerr)?;
        // The run's slot, not the clock: a resumed run reads the same two days.
        let today = run.key.scheduled_at.date_naive();
        let mail_days = reportable_days(&*self.mail_counts, today)
            .await
            .map_err(lerr)?;
        let mut days: Vec<String> = mail_days.iter().map(|d| d.line()).collect();
        let counted = day_counts::lines(&*self.mail_counts, today).await;
        days.extend(counted.map_err(lerr)?);
        let subject = if !found.is_empty() || !days.is_empty() {
            "OpsAgent: failures in the last 24 hours"
        } else if !found.skipped_billing.is_empty() {
            // Not a failure, but scans did not run: it must not read as a quiet night.
            "OpsAgent: nightly notice, scans skipped for billing"
        } else {
            "OpsAgent: nightly notice, nothing failed"
        };
        let mut text = body(&signups, &found, &days);
        if is_monday(run.key.scheduled_at) {
            let week = self.failures.week_until(run.key.scheduled_at).await;
            text = format!("{}\n\n{text}", week.map_err(lerr)?.line());
        }
        let mail = Mail {
            to: self.contact_to.clone(),
            subject: subject.into(),
            html: Some(branded(subject, &text, None)),
            text,
            idempotency_key: Some(format!("operator_notice:{}", run.id)),
            ..Default::default()
        };
        with_effect(
            self.uow.ledger(),
            run.id,
            "operator_notice",
            true,
            || async {
                self.mailer.send(mail).await.map_err(|_| {
                    tracing::error!(error_code = "mail_failed", "operator notice mail failed");
                    LedgerError::Job {
                        code: "mail_failed".into(),
                        retry: true,
                    }
                })?;
                Ok(None)
            },
        )
        .await?;
        Ok(outcome(true))
    }
}

fn outcome(mailed: bool) -> ChunkOutcome {
    ChunkOutcome {
        stats: json!({ "mailed": mailed }),
        ..Default::default()
    }
}

fn line(label: &str, by_kind: &[(String, i64)]) -> String {
    let total: i64 = by_kind.iter().map(|(_, n)| n).sum();
    let kinds: Vec<_> = by_kind.iter().map(|(k, n)| format!("{k} {n}")).collect();
    format!("{label}: {total} ({})", kinds.join(", "))
}

/// `days`: the per-day lines (mail, then counted failures), one each.
fn body(s: &Signups, f: &Failures, days: &[String]) -> String {
    let days: String = days.iter().map(|d| format!("{d}\n")).collect();
    format!(
        "In the last 24 hours:\n\nSign-ups: {} users, {} organisations. Waitlist: {}.\n{}\n{}\n{}\n{days}\nDetails are in the logs.",
        s.users,
        s.organisations,
        s.waitlist,
        line("Dead jobs", &f.dead_jobs),
        line("Failed runs", &f.failed_runs),
        line("Scans skipped for billing", &f.skipped_billing)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mailers::counting::DayCount;

    fn k(s: &str, n: i64) -> (String, i64) {
        (s.into(), n)
    }

    #[test]
    fn body_counts_by_kind_and_handles_an_empty_side() {
        let f = Failures {
            dead_jobs: vec![k("full_scan", 2), k("verify", 1)],
            failed_runs: vec![],
            skipped_billing: vec![],
        };
        let text = body(&Signups::default(), &f, &[]);
        assert!(
            text.contains("Dead jobs: 3 (full_scan 2, verify 1)"),
            "{text}"
        );
        assert!(text.contains("Failed runs: 0 ()"), "{text}");
        assert!(text.contains("Scans skipped for billing: 0 ()"), "{text}");
        assert!(
            text.ends_with("Scans skipped for billing: 0 ()\n\nDetails are in the logs."),
            "{text}"
        );
        assert!(
            text.contains("Sign-ups: 0 users, 0 organisations. Waitlist: 0.\nDead jobs"),
            "{text}"
        );
        assert!(!f.is_empty() && Failures::default().is_empty());
    }

    #[test]
    fn body_has_one_line_per_reported_mail_day() {
        let day = DayCount {
            day: chrono::NaiveDate::from_ymd_opt(2026, 11, 18).unwrap(),
            sent: 80.into(),
            refused: 2.into(),
        };
        let billing = "Billing on 2026-11-18: 2 organisations could not be processed.";
        let text = body(
            &Signups::default(),
            &Failures::default(),
            &[day.line(), billing.into()],
        );
        let line = "Mail on 2026-11-18: 80 sent, 2 not sent. The Resend plan stops at 100 a day.";
        assert!(
            text.contains(&format!("\n{line}\n{billing}\n\nDetails")),
            "{text}"
        );
    }
}
