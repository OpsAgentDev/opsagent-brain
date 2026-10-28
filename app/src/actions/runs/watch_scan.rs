//! `watch_scan` (urgent-alerts spec): the 15-minute subset of `full_scan`. It reads only the
//! services below, keeps only the variants built entirely from them, and never resolves
//! findings, marks resources gone or scores the connection.
use std::collections::BTreeSet;

use opsagent_checks::Check;
use opsagent_core::finding::FindingDraft;

/// The inventory services a watch scan reads.
pub(super) const WATCH_SERVICES: [&str; 3] = ["sg", "rds", "cloudtrail"];

/// The checks a watch scan runs, with every service each one reads.
const WATCH_CHECKS: [(&str, &[&str]); 2] = [("03", &["sg", "rds"]), ("06", &["cloudtrail"])];

/// (check, variant) a watch scan keeps; every other draft is dropped. Check 06's are the two
/// built only from `cloudtrail` resources (`detection_off:<region>` needs guardduty and
/// `no_retention` needs logs).
pub(super) const WATCH_VARIANTS: [(&str, &str); 7] = [
    ("03", "public_snapshot"),
    ("03", "public_database"),
    ("03", "sg_open_admin_port"),
    ("03", "sg_open_unused"),
    ("03", "sg_open_web_on_lb"),
    ("06", "trail_effectively_off"),
    ("06", "trail_status_unknown"),
];

/// The watch checks of `all`, minus any that needs a service whose read failed this run
/// (absence-based variants such as "trail off" must not fire on a failed read). The second
/// list is the skipped check ids.
pub(super) fn checks(
    all: Vec<Box<dyn Check>>,
    unavailable: &BTreeSet<String>,
) -> (Vec<Box<dyn Check>>, Vec<&'static str>) {
    let (mut run, mut skipped) = (vec![], vec![]);
    for ch in all {
        let Some((_, needs)) = WATCH_CHECKS.iter().find(|(id, _)| *id == ch.id()) else {
            continue;
        };
        if needs.iter().any(|s| unavailable.contains(*s)) {
            skipped.push(ch.id());
        } else {
            run.push(ch);
        }
    }
    (run, skipped)
}

/// True for a draft in `WATCH_VARIANTS`.
pub(super) fn allowed(d: &FindingDraft) -> bool {
    WATCH_VARIANTS.contains(&(d.key.check_id.as_str(), d.key.variant.as_str()))
}

#[cfg(test)]
mod tests {
    use opsagent_core::finding::{FindingKey, Severity};
    use uuid::Uuid;

    use super::*;

    fn draft(check_id: &str, variant: &str) -> FindingDraft {
        FindingDraft {
            key: FindingKey {
                connection_id: Uuid::nil(),
                check_id: check_id.into(),
                resource_identity: "r".into(),
                variant: variant.into(),
            },
            severity: Severity::Critical,
            title: "t".into(),
            summary: "s".into(),
            next_step: "n".into(),
            cost_monthly_usd: None,
            evidence: vec![],
        }
    }

    #[test]
    fn only_watch_variants_are_allowed() {
        assert!(allowed(&draft("03", "public_snapshot")));
        assert!(allowed(&draft("06", "trail_effectively_off")));
        for (c, v) in [
            ("03", "bucket_no_bpa"),
            ("06", "detection_off:us-east-1"),
            ("06", "no_retention"),
            ("02", "public_snapshot"),
        ] {
            assert!(!allowed(&draft(c, v)), "{c} {v}");
        }
    }

    #[test]
    fn watch_checks_skip_on_a_failed_service() {
        let ids = |unavailable: &[&str]| {
            let down = unavailable.iter().map(|s| s.to_string()).collect();
            let (run, skipped) = checks(opsagent_checks::all(), &down);
            (run.iter().map(|c| c.id()).collect::<Vec<_>>(), skipped)
        };
        assert_eq!(ids(&[]), (vec!["03", "06"], vec![]));
        assert_eq!(ids(&["rds"]), (vec!["06"], vec!["03"]));
        assert_eq!(ids(&["cloudtrail", "s3"]), (vec!["03"], vec!["06"]));
    }
}
