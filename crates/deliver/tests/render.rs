mod common;

use common::*;
use opsagent_core::connection::ConnectionStatus;
use opsagent_core::finding::Severity;
use opsagent_deliver::briefing::build_briefing;
use opsagent_deliver::model::{EventKind, FindingStatus, SpendSnapshot, WeeklyExtras};
use opsagent_deliver::route::{resolve, Recipient, Route};
use opsagent_deliver::weekly::build_weekly;
use opsagent_deliver::{render_html, render_slack, render_text};

const EVIDENCE: &str = "EVIDENCE-EXCERPT-arn:aws:iam::123:role/x";

#[test]
fn briefing_text_stays_under_slack_limit_with_huge_titles() {
    let long = "x".repeat(5_000);
    let mut fs: Vec<_> = (0..30).map(|_| opened(Severity::Critical, &long)).collect();
    fs.push(finding(
        "02",
        Severity::High,
        FindingStatus::Open,
        &[EventKind::Escalated],
        &long,
    ));
    let b = build_briefing(&conn(), &fs, since(), now(), LINK_BASE).expect("briefing");
    let t = render_text(&b);
    assert!(t.chars().count() <= 3_900, "len {}", t.chars().count());
    assert!(t.contains("30"), "total count shown: {t}");
    assert!(t.contains(LINK_BASE));
}

#[test]
fn briefing_text_has_titles_but_no_evidence() {
    // Evidence is not part of the snapshot; the resource identity must not leak either.
    let mut f = opened(Severity::High, "bucket is public");
    f.key.resource_identity = EVIDENCE.into();
    let b = build_briefing(&conn(), &[f], since(), now(), LINK_BASE).expect("briefing");
    let t = render_text(&b);
    assert!(t.contains("bucket is public"));
    assert!(!t.contains(EVIDENCE));
}

#[test]
fn briefing_text_escapes_slack_control_chars() {
    let b = build_briefing(
        &conn(),
        &[opened(Severity::High, "<!channel> & <http://evil|x>")],
        since(),
        now(),
        LINK_BASE,
    )
    .expect("briefing");
    let t = render_text(&b);
    assert!(!t.contains("<!channel>"));
    assert!(t.contains("&lt;!channel&gt; &amp;"));
}

#[test]
fn first_scan_text_is_counts_and_link() {
    let mut c = conn();
    c.first_scan_at = Some(now());
    let b = build_briefing(
        &c,
        &[opened(Severity::Critical, "secret title")],
        since(),
        now(),
        LINK_BASE,
    )
    .expect("briefing");
    let t = render_text(&b);
    assert!(t.to_lowercase().contains("first scan"));
    assert!(t.contains("2 critical"));
    assert!(!t.contains("secret title"));
}

fn weekly_with_title(title: &str) -> String {
    let spend = SpendSnapshot {
        this_week_usd: 10.0,
        last_week_usd: 5.0,
        anomalies: vec![],
    };
    let mut f = finding("01", Severity::High, FindingStatus::Open, &[], title);
    f.cost_monthly_usd = Some(50.0);
    let mut c = conn();
    c.display_name = "<b>acme</b>".into();
    let w = build_weekly(
        &c,
        &[f],
        Some(&spend),
        &WeeklyExtras::default(),
        now(),
        LINK_BASE,
    );
    render_html(&w)
}

#[test]
fn weekly_html_escapes_user_strings() {
    let h = weekly_with_title("<script>alert(1)</script>");
    assert!(!h.contains("<script>"), "{h}");
    assert!(h.contains("script&#62;alert(1)"), "escaped, not dropped");
    assert!(!h.contains("<b>acme</b>"));
    assert!(h.contains("Need a human?"));
    assert!(h.contains("https://harun.dev"));
}

fn recipient(email: &str) -> Recipient {
    Recipient {
        id: uuid::Uuid::nil(),
        email: email.into(),
        member: true,
    }
}

#[test]
fn route_falls_back_to_org_when_connection_route_is_none() {
    let org = Route {
        slack_channel: Some("C-ORG".into()),
        recipients: vec![recipient("owner@example.test")],
    };
    assert_eq!(resolve(None, org.clone()), org);
}

#[test]
fn route_falls_back_field_by_field() {
    let org = Route {
        slack_channel: Some("C-ORG".into()),
        recipients: vec![recipient("owner@example.test")],
    };
    let only_channel = Route {
        slack_channel: Some("C-CLIENT".into()),
        recipients: vec![],
    };
    let r = resolve(Some(only_channel), org.clone());
    assert_eq!(r.slack_channel.as_deref(), Some("C-CLIENT"));
    assert_eq!(r.recipients, org.recipients);

    let only_people = Route {
        slack_channel: None,
        recipients: vec![recipient("client@example.test")],
    };
    let r = resolve(Some(only_people.clone()), org);
    assert_eq!(r.slack_channel.as_deref(), Some("C-ORG"));
    assert_eq!(r.recipients, only_people.recipients);
}

fn degraded_with_long_reason() -> opsagent_deliver::model::ConnectionSnapshot {
    let mut c = conn();
    c.status = ConnectionStatus::Degraded;
    c.status_reason = Some("r".repeat(2_000));
    c
}

#[test]
fn escaped_titles_and_long_reason_still_fit() {
    let amp = "&".repeat(200);
    let fs: Vec<_> = (0..10).map(|_| opened(Severity::Critical, &amp)).collect();
    let b = build_briefing(&degraded_with_long_reason(), &fs, since(), now(), LINK_BASE)
        .expect("briefing");
    let t = render_text(&b);
    assert!(t.len() <= 3_900, "len {}", t.len());
    assert!(!t.contains(&"r".repeat(201)), "reason capped");
    assert!(t.contains('\u{2026}'), "ellipsis on capped text");
}

#[test]
fn oversized_briefing_drops_items_but_keeps_counts_and_link() {
    let base = format!("https://{}.test", "l".repeat(2_000));
    let fs: Vec<_> = (0..10)
        .map(|i| opened(Severity::Critical, &format!("{i}{}", "t".repeat(300))))
        .collect();
    let b =
        build_briefing(&degraded_with_long_reason(), &fs, since(), now(), &base).expect("briefing");
    let t = render_text(&b);
    assert!(t.len() <= 3_900, "len {}", t.len());
    assert!(t.contains(&base), "link kept");
    assert!(t.contains("Open now:"));
    assert!(t.contains("0ttt"), "first item kept");
    assert!(!t.contains("9ttt"), "last item dropped");
    assert!(t.contains("more on the dashboard"));
}

#[test]
fn weekly_slack_is_escaped_and_fits() {
    let spend = SpendSnapshot {
        this_week_usd: 10.0,
        last_week_usd: 5.0,
        anomalies: vec![],
    };
    let f = finding(
        "02",
        Severity::High,
        FindingStatus::Open,
        &[],
        "<!channel> admin & co",
    );
    let extras = WeeklyExtras {
        would_have_done: vec!["w".repeat(300); 50],
        ..Default::default()
    };
    let w = build_weekly(&conn(), &[f], Some(&spend), &extras, now(), LINK_BASE);
    let t = render_slack(&w);
    assert!(t.len() <= 3_900, "len {}", t.len());
    assert!(!t.contains("<!channel>"));
    assert!(t.contains("&lt;!channel&gt; admin &amp; co"));
    assert!(t.contains("+$5.00"));
    assert!(t.contains("Need a human?"));
    assert!(t.contains("https://harun.dev"));
    assert!(t.contains(LINK_BASE));
}

#[test]
fn untracked_spend_renders_as_not_tracked_not_zero() {
    let w = build_weekly(
        &conn(),
        &[],
        None,
        &WeeklyExtras::default(),
        now(),
        LINK_BASE,
    );
    for (name, out) in [
        ("text", render_text(&w)),
        ("slack", render_slack(&w)),
        ("html", render_html(&w)),
    ] {
        assert!(out.contains("not tracked yet"), "{name}: {out}");
        assert!(!out.contains("$0.00"), "{name}: {out}");
    }
}

#[test]
fn briefing_marks_alerted_items() {
    let mut c = conn();
    c.timezone = "Asia/Dhaka".into();
    let mut alerted = opened(Severity::Critical, "public snapshot");
    alerted.alerted_at = Some(now() - chrono::Duration::minutes(48)); // 07:12 UTC
    let fs = vec![alerted, opened(Severity::High, "open port")];
    let t = render_text(&build_briefing(&c, &fs, since(), now(), LINK_BASE).expect("briefing"));
    assert!(t.contains("public snapshot (alerted 13:12)\n"), "{t}");
    assert!(t.contains("open port\n"), "{t}");
}
