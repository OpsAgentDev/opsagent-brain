mod common;

use chrono::Duration;
use common::*;
use opsagent_core::connection::ConnectionStatus;
use opsagent_core::finding::Severity;
use opsagent_deliver::briefing::build_briefing;
use opsagent_deliver::model::{Briefing, EventKind, FindingStatus};

#[test]
fn nothing_changed_is_none() {
    let quiet = vec![
        finding(
            "01",
            Severity::High,
            FindingStatus::Open,
            &[EventKind::Seen],
            "old",
        ),
        finding("01", Severity::Low, FindingStatus::Open, &[], "older"),
    ];
    assert_eq!(
        build_briefing(&conn(), &quiet, since(), now(), LINK_BASE),
        None
    );
    assert_eq!(
        build_briefing(&conn(), &[], since(), now(), LINK_BASE),
        None
    );
}

#[test]
fn first_scan_after_since_is_counts_and_link_only() {
    let mut c = conn();
    c.first_scan_at = Some(now() - Duration::hours(1));
    let fs = vec![opened(Severity::Critical, "public snapshot")];
    match build_briefing(&c, &fs, since(), now(), LINK_BASE) {
        Some(Briefing::FirstScan { counts, link }) => {
            assert_eq!(counts, c.counts_by_severity);
            assert!(link.starts_with(LINK_BASE));
            assert!(link.contains(&c.id.to_string()));
        }
        other => panic!("expected first scan, got {other:?}"),
    }
}

#[test]
fn fourteen_new_criticals_cap_at_ten_and_count_fourteen() {
    let fs: Vec<_> = (0..14)
        .map(|i| opened(Severity::Critical, &format!("crit {i}")))
        .collect();
    let Some(Briefing::Daily {
        new_critical_high,
        escalated,
        resolved_critical,
        counts,
        ..
    }) = build_briefing(&conn(), &fs, since(), now(), LINK_BASE)
    else {
        panic!("expected daily");
    };
    assert_eq!(
        new_critical_high.len() + escalated.len() + resolved_critical.len(),
        10
    );
    assert_eq!(new_critical_high.len(), 10);
    assert_eq!(counts.new_critical_high, 14);
}

#[test]
fn sections_are_ordered_and_cap_spans_them() {
    let mut fs: Vec<_> = (0..8)
        .map(|i| opened(Severity::High, &format!("new {i}")))
        .collect();
    fs.push(opened(Severity::Critical, "new crit"));
    fs.push(opened(Severity::Medium, "medium is not news"));
    for i in 0..3 {
        fs.push(finding(
            "02",
            Severity::High,
            FindingStatus::Open,
            &[EventKind::Seen, EventKind::Escalated],
            &format!("esc {i}"),
        ));
    }
    fs.push(finding(
        "03",
        Severity::Critical,
        FindingStatus::Resolved,
        &[EventKind::Resolved],
        "fixed",
    ));
    let Some(Briefing::Daily {
        new_critical_high,
        escalated,
        resolved_critical,
        counts,
        ..
    }) = build_briefing(&conn(), &fs, since(), now(), LINK_BASE)
    else {
        panic!("expected daily");
    };
    // Critical first within the section; medium never listed.
    assert_eq!(new_critical_high[0].title, "new crit");
    assert_eq!(new_critical_high.len(), 9);
    assert_eq!(escalated.len(), 1);
    assert!(resolved_critical.is_empty());
    assert_eq!(
        (
            counts.new_critical_high,
            counts.escalated,
            counts.resolved_critical
        ),
        (9, 3, 1)
    );
}

#[test]
fn resolved_critical_alone_is_a_briefing() {
    let fs = vec![finding(
        "03",
        Severity::Critical,
        FindingStatus::Resolved,
        &[EventKind::Resolved],
        "fixed",
    )];
    let Some(Briefing::Daily {
        resolved_critical, ..
    }) = build_briefing(&conn(), &fs, since(), now(), LINK_BASE)
    else {
        panic!("expected daily");
    };
    assert_eq!(resolved_critical[0].title, "fixed");
}

#[test]
fn unhealthy_connection_is_reported_even_without_findings() {
    let mut c = conn();
    c.status = ConnectionStatus::Degraded;
    c.status_reason = Some("missing permissions".into());
    let Some(Briefing::Daily {
        health: Some(h), ..
    }) = build_briefing(&c, &[], since(), now(), LINK_BASE)
    else {
        panic!("expected daily with health");
    };
    assert_eq!(h.status, ConnectionStatus::Degraded);
}
