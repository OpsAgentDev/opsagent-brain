//! Counts every mail this app sends, per UTC day, so the nightly operator notice can warn
//! before the mail plan's daily stop. Counts only: no address, subject or body.
use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use chrono::NaiveDate;
use opsagent_core::repo::Clock;
use sea_orm::prelude::Decimal;

use super::{Mail, Mailer};
use crate::{
    actions::{ai::CreditTally, DAY_SECS},
    error::AppResult,
};

/// Resend's Free plan refuses mail past this many a day.
const DAILY_STOP: i64 = 100;
/// A day with this many sent is reported: room to act before Resend's Free plan stops.
const WARN_AT: i64 = 80;
/// The notice reads yesterday and today; a third day covers a late run.
pub(crate) const KEEP_SECS: i64 = 3 * DAY_SECS;
/// A counter that does not answer is given up on, so a send never waits on it for long.
pub(crate) const COUNT_TIMEOUT: Duration = Duration::from_secs(2);

fn key(outcome: &str, day: NaiveDate) -> String {
    format!("mail:{outcome}:{day}")
}

/// Wraps the one mailer the app is built with: each send adds one to the day's `sent`
/// (the provider accepted it) or `refused` (it did not) counter.
pub struct CountingMailer {
    inner: Arc<dyn Mailer>,
    tally: Arc<dyn CreditTally>,
    clock: Arc<dyn Clock>,
}

impl CountingMailer {
    pub fn new(inner: Arc<dyn Mailer>, tally: Arc<dyn CreditTally>, clock: Arc<dyn Clock>) -> Self {
        Self {
            inner,
            tally,
            clock,
        }
    }
}

#[async_trait]
impl Mailer for CountingMailer {
    async fn send(&self, mail: Mail) -> std::result::Result<(), String> {
        let sent = self.inner.send(mail).await;
        let outcome = if sent.is_ok() { "sent" } else { "refused" };
        let key = key(outcome, self.clock.now().date_naive());
        let add = self.tally.add(&key, Decimal::ONE, KEEP_SECS);
        if !matches!(tokio::time::timeout(COUNT_TIMEOUT, add).await, Ok(Ok(()))) {
            tracing::warn!(
                error_code = "mail_count_failed",
                outcome,
                "mail not counted"
            );
        }
        sent
    }
}

/// One UTC day's sends by this app (not Resend's own tally).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DayCount {
    pub day: NaiveDate,
    pub sent: Decimal,
    pub refused: Decimal,
}

impl DayCount {
    fn reportable(&self) -> bool {
        self.refused > Decimal::ZERO || self.sent >= Decimal::from(WARN_AT)
    }

    pub fn line(&self) -> String {
        format!(
            "Mail on {}: {} sent, {} not sent. The Resend plan stops at {DAILY_STOP} a day.",
            self.day, self.sent, self.refused
        )
    }
}

/// The days worth a line in the notice, of the day before `today` and `today`: any mail
/// refused, or `WARN_AT` or more sent.
pub async fn reportable_days(
    tally: &dyn CreditTally,
    today: NaiveDate,
) -> AppResult<Vec<DayCount>> {
    let mut days = Vec::new();
    for day in [today.pred_opt(), Some(today)].into_iter().flatten() {
        let count = DayCount {
            day,
            sent: tally.total(&key("sent", day)).await?,
            refused: tally.total(&key("refused", day)).await?,
        };
        if count.reportable() {
            days.push(count);
        }
    }
    Ok(days)
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::*;
    use crate::{
        adapters::memory::{FixedClock, MemRateLimiter},
        error::AppError,
        mailers::{CaptureMailer, FailingMailer},
    };

    fn day(d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 11, d).unwrap()
    }

    fn mailer(inner: Arc<dyn Mailer>, tally: Arc<dyn CreditTally>, d: u32) -> CountingMailer {
        // 23:59 UTC: the day is the UTC date, whatever the local one is.
        let at = Utc.with_ymd_and_hms(2026, 11, d, 23, 59, 0).unwrap();
        CountingMailer::new(inner, tally, Arc::new(FixedClock(at)))
    }

    async fn send_n(m: &CountingMailer, n: usize) {
        for _ in 0..n {
            let _ = m.send(Mail::default()).await;
        }
    }

    #[tokio::test]
    async fn sent_and_refused_are_counted_on_their_utc_day() {
        let tally = Arc::new(MemRateLimiter::default());
        let ok = Arc::new(CaptureMailer::default());
        send_n(&mailer(ok.clone(), tally.clone(), 18), 2).await;
        send_n(&mailer(ok.clone(), tally.clone(), 19), 1).await;
        let refused = mailer(Arc::new(FailingMailer), tally.clone(), 19);
        assert!(refused.send(Mail::default()).await.is_err());

        assert_eq!(ok.sent().len(), 3);
        let total = |k: &'static str| {
            let tally = tally.clone();
            async move { tally.total(k).await.unwrap() }
        };
        assert_eq!(total("mail:sent:2026-11-18").await, Decimal::from(2));
        assert_eq!(total("mail:sent:2026-11-19").await, Decimal::ONE);
        assert_eq!(total("mail:refused:2026-11-19").await, Decimal::ONE);
        assert_eq!(total("mail:refused:2026-11-18").await, Decimal::ZERO);
    }

    struct DownTally;

    #[async_trait]
    impl CreditTally for DownTally {
        async fn total(&self, _: &str) -> AppResult<Decimal> {
            Err(AppError::Internal("down".into()))
        }
        async fn add(&self, _: &str, _: Decimal, _: i64) -> AppResult<()> {
            Err(AppError::Internal("down".into()))
        }
    }

    #[tokio::test]
    async fn a_failing_counter_does_not_fail_a_send() {
        let ok = Arc::new(CaptureMailer::default());
        let m = mailer(ok.clone(), Arc::new(DownTally), 19);
        assert_eq!(m.send(Mail::default()).await, Ok(()));
        assert_eq!(ok.sent().len(), 1);
    }

    #[tokio::test]
    async fn reports_a_refused_mail_and_80_sent_and_is_silent_at_79() {
        let tally = Arc::new(MemRateLimiter::default());
        let ok: Arc<dyn Mailer> = Arc::new(CaptureMailer::default());
        send_n(&mailer(ok.clone(), tally.clone(), 18), 79).await;
        assert!(reportable_days(&*tally, day(19)).await.unwrap().is_empty());

        send_n(&mailer(ok.clone(), tally.clone(), 18), 1).await;
        let days = reportable_days(&*tally, day(19)).await.unwrap();
        assert_eq!(days.len(), 1);
        assert_eq!(
            days[0].line(),
            "Mail on 2026-11-18: 80 sent, 0 not sent. The Resend plan stops at 100 a day."
        );
        // Two days on, the 18th is no longer reported.
        assert!(reportable_days(&*tally, day(20)).await.unwrap().is_empty());

        send_n(&mailer(Arc::new(FailingMailer), tally.clone(), 19), 1).await;
        let days = reportable_days(&*tally, day(19)).await.unwrap();
        assert_eq!(
            days[1].line(),
            "Mail on 2026-11-19: 0 sent, 1 not sent. The Resend plan stops at 100 a day."
        );
    }
}
