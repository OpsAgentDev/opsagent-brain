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

/// The rows of the newest `CHECK_DAYS` days, anchored on the newest day read (not today).
pub(super) fn for_checks(rows: &[CostRow]) -> Vec<CostRow> {
    let Some(newest) = rows.iter().map(|r| r.date).max() else {
        return vec![];
    };
    let from = newest - Days::new(CHECK_DAYS - 1);
    rows.iter().filter(|r| r.date >= from).cloned().collect()
}

/// One row per `(day, service)` (amounts summed), ready to store. An amount that is not a
/// finite number has no row.
pub(super) fn to_stored(rows: &[CostRow]) -> Vec<CostDay> {
    let mut by_key: BTreeMap<(NaiveDate, &str), Decimal> = BTreeMap::new();
    for r in rows {
        if let Ok(amount) = Decimal::try_from(r.amount_usd) {
            *by_key.entry((r.date, &r.service)).or_default() += amount;
        }
    }
    by_key
        .into_iter()
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

    #[test]
    fn checks_see_the_newest_30_days_whatever_today_is() {
        let rows: Vec<_> = (0..60).map(|d| row(d, "ec2", 1.0)).collect();
        let seen = for_checks(&rows);
        assert_eq!(seen.len(), 30);
        assert_eq!(seen[0].date, rows[30].date);
        assert!(for_checks(&[]).is_empty());
        // Fewer than 30 days: all of them.
        assert_eq!(for_checks(&rows[..10]).len(), 10);
    }

    #[test]
    fn stored_rows_are_one_per_day_and_service() {
        let rows = [
            row(0, "ec2", 1.25),
            row(0, "ec2", 0.5),
            row(0, "s3", 2.0),
            row(1, "ec2", f64::NAN),
        ];
        let stored = to_stored(&rows);
        let got: Vec<_> = stored
            .iter()
            .map(|c| (c.service.as_str(), c.amount_usd.to_string()))
            .collect();
        assert_eq!(got, [("ec2", "1.75".to_owned()), ("s3", "2".to_owned())]);
    }
}
