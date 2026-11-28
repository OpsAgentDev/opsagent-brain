//! The cost read of a full scan: 60 days are stored (the Spend page), the newest 30 feed
//! check 01, whose baselines must not move when the read widens.
use std::collections::BTreeMap;

use chrono::{Days, NaiveDate};
use opsagent_connectors::CostRow;
use opsagent_core::resource::CostDay;
use sea_orm::prelude::Decimal;

/// Days a full scan reads and stores.
pub(super) const READ_DAYS: u32 = 60;
/// Days check 01 sees: the newest ones, as before the read widened.
const CHECK_DAYS: u64 = 30;

/// The rows of the 30 days check 01 saw before the read widened: `today - 30` through
/// yesterday, so a day AWS returns no row for moves nothing. shortcut: data that ends before
/// that window (a fixture, a long-dead account) anchors on its own newest day instead of
/// feeding the check nothing; revisit if a stale real account should see no cost rows.
pub(super) fn for_checks(rows: &[CostRow], today: NaiveDate) -> Vec<CostRow> {
    let from = today - Days::new(CHECK_DAYS);
    let Some(newest) = rows.iter().map(|r| r.date).max() else {
        return vec![];
    };
    let from = if newest < from {
        newest - Days::new(CHECK_DAYS - 1)
    } else {
        from
    };
    rows.iter().filter(|r| r.date >= from).cloned().collect()
}

/// Largest magnitude `numeric(14,4)` holds, exclusive.
const MAX_STORED: i64 = 10_000_000_000;

/// One row per `(day, service)` (amounts summed; credits are negative), ready to store. An
/// amount that is not a finite number, or that `numeric(14,4)` cannot hold, has no row.
pub(super) fn to_stored(rows: &[CostRow]) -> Vec<CostDay> {
    let mut by_key: BTreeMap<(NaiveDate, &str), Decimal> = BTreeMap::new();
    for r in rows {
        if let Ok(amount) = Decimal::try_from(r.amount_usd) {
            *by_key.entry((r.date, &r.service)).or_default() += amount;
        }
    }
    by_key
        .into_iter()
        .filter(|(_, amount)| amount.abs() < Decimal::from(MAX_STORED))
        .map(|((day, service), amount_usd)| CostDay {
            day,
            service: service.to_owned(),
            amount_usd,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(day: u32, service: &str, usd: f64) -> CostRow {
        CostRow {
            date: NaiveDate::from_ymd_opt(2026, 9, 1).unwrap() + Days::new(u64::from(day)),
            service: service.into(),
            amount_usd: usd,
        }
    }

    fn day(n: i64) -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 9, 1).unwrap() + chrono::Duration::days(n)
    }

    #[test]
    fn checks_see_the_30_days_ending_yesterday_even_with_a_gap_day() {
        // `today` is day 60; AWS read days 0..=59 but has no row for yesterday (day 59).
        let rows: Vec<_> = (0..59).map(|d| row(d, "ec2", 1.0)).collect();
        let seen = for_checks(&rows, day(60));
        // Days 30..=58: 29 rows, as the 30-day read returned before the read widened.
        assert_eq!(seen.len(), 29);
        assert_eq!(seen[0].date, day(30));
        // No gap: 30..=59.
        let full: Vec<_> = (0..60).map(|d| row(d, "ec2", 1.0)).collect();
        assert_eq!(for_checks(&full, day(60)).len(), 30);
    }

    #[test]
    fn checks_anchor_on_the_newest_day_when_the_data_predates_the_window() {
        let rows: Vec<_> = (0..60).map(|d| row(d, "ec2", 1.0)).collect();
        let seen = for_checks(&rows, day(500));
        assert_eq!(seen.len(), 30);
        assert_eq!(seen[0].date, day(30));
        assert!(for_checks(&[], day(60)).is_empty());
        assert_eq!(for_checks(&rows[..10], day(500)).len(), 10);
    }

    #[test]
    fn stored_rows_are_one_per_day_and_service() {
        let rows = [
            row(0, "ec2", 1.25),
            row(0, "ec2", 0.5),
            row(0, "s3", 2.0),
            row(1, "ec2", f64::NAN),
            // A credit is negative; an amount past numeric(14,4) has no row.
            row(1, "support", -3.5),
            row(1, "s3", 1.0e10),
            row(1, "rds", -1.0e10),
        ];
        let stored = to_stored(&rows);
        let got: Vec<_> = stored
            .iter()
            .map(|c| (c.service.as_str(), c.amount_usd.to_string()))
            .collect();
        let want = [("ec2", "1.75"), ("s3", "2"), ("support", "-3.5")];
        assert_eq!(got, want.map(|(s, a)| (s, a.to_owned())));
    }
}
