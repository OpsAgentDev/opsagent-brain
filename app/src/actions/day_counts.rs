//! Per-UTC-day counts of failures nobody else is told about, for the nightly operator notice
//! (launch-readiness.md, J5). Counted the way mail is (`mailers::counting`): one counter per
//! kind and day, three days kept. Counts only: no organisation, event or check is named.
use std::sync::Arc;

use chrono::NaiveDate;
use opsagent_core::repo::Clock;
use sea_orm::prelude::Decimal;

use crate::{
    actions::ai::CreditTally,
    error::AppResult,
    mailers::counting::{COUNT_TIMEOUT, KEEP_SECS},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Counted {
    /// An organisation whose nightly billing pass failed.
    BillingOrg,
    /// A paid top-up or human review the webhook matched to no organisation or request.
    UnmatchedPayment,
    /// A check that panicked or could not read its input in a scan.
    FailedCheck,
}

const ALL: [Counted; 3] = [
    Counted::BillingOrg,
    Counted::UnmatchedPayment,
    Counted::FailedCheck,
];

impl Counted {
    fn key(self, day: NaiveDate) -> String {
        let kind = match self {
            Self::BillingOrg => "billing:failed",
            Self::UnmatchedPayment => "payment:unmatched",
            Self::FailedCheck => "check:failed",
        };
        format!("{kind}:{day}")
    }

    fn line(self, day: NaiveDate, n: Decimal) -> String {
        match self {
            Self::BillingOrg => {
                format!("Billing on {day}: {n} organisations could not be processed.")
            }
            Self::UnmatchedPayment => {
                format!("Payments on {day}: {n} paid events matched no organisation or request.")
            }
            Self::FailedCheck => {
                format!("Checks on {day}: {n} checks panicked or could not read their input.")
            }
        }
    }
}

/// Adds to the day's counters. Never fails and never waits long: what it counts goes on.
#[derive(Clone)]
pub struct DayCounter {
    tally: Arc<dyn CreditTally>,
    clock: Arc<dyn Clock>,
}

impl DayCounter {
    pub fn new(tally: Arc<dyn CreditTally>, clock: Arc<dyn Clock>) -> Self {
        Self { tally, clock }
    }

    pub async fn add(&self, what: Counted, n: u64) {
        if n == 0 {
            return;
        }
        let key = what.key(self.clock.now().date_naive());
        let add = self.tally.add(&key, Decimal::from(n), KEEP_SECS);
        if !matches!(tokio::time::timeout(COUNT_TIMEOUT, add).await, Ok(Ok(()))) {
            tracing::warn!(error_code = "day_count_failed", kind = ?what, "failure not counted");
        }
    }
}

/// One notice line per kind and day above zero, of the day before `today` and `today`.
pub async fn lines(tally: &dyn CreditTally, today: NaiveDate) -> AppResult<Vec<String>> {
    let mut out = Vec::new();
    for day in [today.pred_opt(), Some(today)].into_iter().flatten() {
        for what in ALL {
            let n = tally.total(&what.key(day)).await?;
            if n > Decimal::ZERO {
                out.push(what.line(day, n));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use async_trait::async_trait;
    use chrono::{TimeZone, Utc};

    use super::*;
    use crate::{
        adapters::memory::{FixedClock, MemRateLimiter},
        error::AppError,
    };

    fn day(d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 11, d).unwrap()
    }

    /// A counter on 2026-11-`d`, 23:59 UTC, over `tally`.
    pub(crate) fn counter(tally: Arc<dyn CreditTally>, d: u32) -> DayCounter {
        let at = Utc.with_ymd_and_hms(2026, 11, d, 23, 59, 0).unwrap();
        DayCounter::new(tally, Arc::new(FixedClock(at)))
    }

    #[tokio::test]
    async fn each_kind_has_its_own_line_and_zero_is_silent() {
        let tally = Arc::new(MemRateLimiter::default());
        assert!(lines(&*tally, day(19)).await.unwrap().is_empty());
        let c = counter(tally.clone(), 18);
        c.add(Counted::BillingOrg, 0).await;
        assert!(lines(&*tally, day(19)).await.unwrap().is_empty());

        c.add(Counted::BillingOrg, 2).await;
        c.add(Counted::UnmatchedPayment, 1).await;
        counter(tally.clone(), 19)
            .add(Counted::FailedCheck, 3)
            .await;
        assert_eq!(
            lines(&*tally, day(19)).await.unwrap(),
            [
                "Billing on 2026-11-18: 2 organisations could not be processed.",
                "Payments on 2026-11-18: 1 paid events matched no organisation or request.",
                "Checks on 2026-11-19: 3 checks panicked or could not read their input.",
            ]
        );
        // Two days on, the 18th is no longer reported.
        assert!(lines(&*tally, day(20)).await.unwrap().len() == 1);
        assert_eq!(
            tally.total("billing:failed:2026-11-18").await.unwrap(),
            Decimal::from(2)
        );
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
    async fn a_failing_counter_is_swallowed() {
        counter(Arc::new(DownTally), 19)
            .add(Counted::FailedCheck, 1)
            .await;
    }
}
