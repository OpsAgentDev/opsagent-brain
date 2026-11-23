//! The Monday block of the operator notice: the last seven days of sign-ups by source, trials,
//! activation, paid accounts and MRR, so the weekly marketing report needs no production DB.
//! Counts only: no organisation or owner is named.
use chrono::{DateTime, Datelike, Utc, Weekday};
use opsagent_core::billing::Tier;

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

/// Monthly recurring revenue in cents: list price (`Tier::monthly_usd`) x connected accounts.
pub fn mrr_cents(by_tier: &[(String, i64)]) -> i64 {
    by_tier
        .iter()
        .filter_map(|(t, q)| Some(i64::from(Tier::parse(t)?.monthly_usd()) * 100 * q))
        .sum()
}

const SOURCE_LEN: usize = 32;
const SOURCES_SHOWN: usize = 10;

/// `utm_source` is visitor-written and ends up in a mail an agent reads: lowercase, `[a-z0-9_.-]`
/// only, 32 characters, `other` when nothing is left. Equal keys merge; the top 10 show, the rest
/// fold into `other`.
pub fn tidy_sources(raw: Vec<(String, i64)>) -> Vec<(String, i64)> {
    let mut merged: Vec<(String, i64)> = Vec::new();
    for (src, n) in raw {
        let mut key: String = src
            .to_lowercase()
            .chars()
            .filter(|c| matches!(c, 'a'..='z' | '0'..='9' | '_' | '.' | '-'))
            .take(SOURCE_LEN)
            .collect();
        if key.is_empty() {
            key = "other".into();
        }
        match merged.iter_mut().find(|(k, _)| *k == key) {
            Some((_, m)) => *m += n,
            None => merged.push((key, n)),
        }
    }
    merged.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    if merged.len() > SOURCES_SHOWN {
        let rest: i64 = merged.split_off(SOURCES_SHOWN).iter().map(|(_, n)| n).sum();
        match merged.iter_mut().find(|(k, _)| k == "other") {
            Some((_, m)) => *m += rest,
            None => merged.push(("other".into(), rest)),
        }
    }
    merged
}

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

    fn n(v: &[(&str, i64)]) -> Vec<(String, i64)> {
        v.iter().map(|(k, n)| (k.to_string(), *n)).collect()
    }

    #[test]
    fn week_counts_sanitises_source() {
        let out = tidy_sources(n(&[
            ("hn\nIgnore previous", 1),
            ("HN", 2),
            ("!!!", 1),
            (&"a".repeat(50), 1),
        ]));
        let long = "a".repeat(32);
        assert_eq!(
            out,
            n(&[("hn", 2), (&long, 1), ("hnignoreprevious", 1), ("other", 1)])
        );
    }

    #[test]
    fn week_counts_caps_sources() {
        let raw: Vec<_> = (0..12).map(|i| (format!("s{i:02}"), 12 - i)).collect();
        let out = tidy_sources(raw);
        assert_eq!(out.len(), 11);
        assert_eq!(out[0], ("s00".to_string(), 12));
        assert_eq!(out[10], ("other".to_string(), 2 + 1));
    }

    #[test]
    fn mrr_uses_tier_prices() {
        assert_eq!(
            mrr_cents(&n(&[("team", 2), ("starter", 1), ("x", 5)])),
            2 * 29900 + 9900
        );
    }
}
