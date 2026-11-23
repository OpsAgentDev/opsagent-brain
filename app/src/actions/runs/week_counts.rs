//! The Monday block of the operator notice: the last seven days of sign-ups by source, trials,
//! activation, paid accounts and MRR, so the weekly marketing report needs no production DB.
//! Counts only: no organisation or owner is named.
use chrono::{DateTime, Datelike, Utc, Weekday};

/// The 7 days ending at the notice time. Internal organisations (owner `@opsagent.dev`) excluded.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WeekCounts {
    /// Organisations created in the window by `utm_source`; no source counts as `direct`.
    pub new_orgs_by_source: Vec<(String, i64)>,
    /// Trials whose start (trial end minus the 14 days) fell in the window.
    pub trials_started: i64,
    /// Organisations created in the window with a verified connection and a finding.
    pub activated: i64,
    /// Organisations on an active paid subscription now.
    pub converted_to_paid: i64,
    pub mrr_cents: i64,
}

/// The notice's own clock is UTC (its run slot), so Monday is the UTC Monday.
pub fn is_monday(at: DateTime<Utc>) -> bool {
    at.weekday() == Weekday::Mon
}

/// List price per connected account and month, in cents, for the SQL's `billing_tier` case.
/// Brain's billing tables hold the tier and quantity, not the amount.
pub const MRR_CASE: &str =
    "CASE billing_tier WHEN 'starter' THEN 9900 WHEN 'team' THEN 29900 WHEN 'scale' THEN 59900 ELSE 0 END";

impl WeekCounts {
    pub fn line(&self) -> String {
        let orgs: Vec<_> = self
            .new_orgs_by_source
            .iter()
            .map(|(s, n)| format!("{s} {n}"))
            .collect();
        format!(
            "Week: orgs {} | trials {} | activated {} | paid {} | MRR ${}",
            if orgs.is_empty() {
                "none".into()
            } else {
                orgs.join(", ")
            },
            self.trials_started,
            self.activated,
            self.converted_to_paid,
            self.mrr_cents / 100
        )
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn line_matches_the_brief_and_monday_is_utc() {
        let w = WeekCounts {
            new_orgs_by_source: vec![("hn".into(), 2), ("direct".into(), 1)],
            trials_started: 3,
            activated: 1,
            ..Default::default()
        };
        assert_eq!(
            w.line(),
            "Week: orgs hn 2, direct 1 | trials 3 | activated 1 | paid 0 | MRR $0"
        );
        assert!(is_monday(
            Utc.with_ymd_and_hms(2026, 11, 23, 23, 59, 0).unwrap()
        ));
        assert!(!is_monday(
            Utc.with_ymd_and_hms(2026, 11, 24, 0, 0, 0).unwrap()
        ));
    }
}
