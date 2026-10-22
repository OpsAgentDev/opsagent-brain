mod common;

use chrono::{Duration, NaiveDate};
use common::*;
use opsagent_core::finding::Severity;
use opsagent_deliver::model::{EventKind, FindingStatus, SpendSnapshot, WeeklyExtras};
use opsagent_deliver::render_text;
use opsagent_deliver::weekly::{build_weekly, NEED_A_HUMAN_URL};

fn spend() -> SpendSnapshot {
    SpendSnapshot {
        this_week_usd: 1250.5,
        last_week_usd: 1000.0,
        anomalies: vec![(NaiveDate::from_ymd_opt(2026, 10, 19).unwrap(), 400.0, 150.0)],
    }
}

fn extras() -> WeeklyExtras {
    WeeklyExtras {
        last_restore_test_on: NaiveDate::from_ymd_opt(2026, 9, 30),
        untagged_spend_pct: Some(12.5),
        would_have_done: vec!["Delete unattached volume vol-1".into()],
    }
}

#[test]
fn recommended_cost_action_is_largest_open_saving() {
    let mut small = finding("01", Severity::Low, FindingStatus::Open, &[], "small");
    small.cost_monthly_usd = Some(10.0);
    let mut big = finding("01", Severity::High, FindingStatus::Open, &[], "big");
    big.cost_monthly_usd = Some(300.0);
    let mut gone = finding("01", Severity::High, FindingStatus::Resolved, &[], "gone");
    gone.cost_monthly_usd = Some(900.0);
    let w = build_weekly(
        &conn(),
        &[small, big, gone],
        &spend(),
        &extras(),
        now(),
        LINK_BASE,
    );
    let action = w.recommended_cost_action.expect("action");
    assert_eq!(action.title, "big");
    assert_eq!(action.savings_monthly_usd, 300.0);
    assert_eq!(w.need_a_human_url, "https://harun.dev");
    assert_eq!(NEED_A_HUMAN_URL, "https://harun.dev");
}

#[test]
fn weekly_text_has_every_section_with_delta_signs() {
    let fs = vec![
        finding(
            "02",
            Severity::High,
            FindingStatus::Open,
            &[EventKind::Opened],
            "admin user",
        ),
        finding(
            "04",
            Severity::Medium,
            FindingStatus::Open,
            &[],
            "no backup plan",
        ),
        finding(
            "05",
            Severity::High,
            FindingStatus::Open,
            &[],
            "cert expires in 20 days",
        ),
    ];
    let w = build_weekly(&conn(), &fs, &spend(), &extras(), now(), LINK_BASE);
    assert_eq!(w.spend.delta_usd, 250.5);
    assert_eq!(w.posture.delta, Some(-5.0));
    assert_eq!((w.iam.open, w.iam.opened, w.iam.resolved), (1, 1, 0));
    let t = render_text(&w);
    for needle in [
        "Spend",
        "+$250.50",
        "2026-10-19",
        "Recommended cost action",
        "Posture score",
        "-5",
        "IAM",
        "Backups",
        "2026-09-30",
        "Certificate",
        "cert expires in 20 days",
        "Untagged spend",
        "12.5%",
        "Awaiting your decision",
        "admin user",
        "would have done",
        "Delete unattached volume vol-1",
        "Need a human?",
        "https://harun.dev",
    ] {
        assert!(t.contains(needle), "missing {needle:?} in:\n{t}");
    }
}

#[test]
fn spend_drop_shows_minus_sign() {
    let mut s = spend();
    s.this_week_usd = 900.0;
    let w = build_weekly(&conn(), &[], &s, &extras(), now(), LINK_BASE);
    assert!(render_text(&w).contains("-$100.00"));
}

#[test]
fn new_connection_says_baselines_forming() {
    let mut c = conn();
    c.first_scan_at = Some(now() - Duration::days(2));
    let w = build_weekly(&c, &[], &spend(), &extras(), now(), LINK_BASE);
    assert!(w.first_week);
    assert!(render_text(&w).contains("first week; baselines forming"));
}
