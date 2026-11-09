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
    assert!(!h.contains("harun.dev"));
    assert!(h.contains("Request a human review"));
    assert!(h.contains(&format!("{LINK_BASE}/settings/human-review")));
}

fn plain_weekly() -> opsagent_deliver::model::Weekly {
    build_weekly(
        &conn(),
        &[],
        None,
        &WeeklyExtras::default(),
        now(),
        LINK_BASE,
    )
}

#[test]
fn human_review_line_only_when_url_set_in_html_and_text() {
    let mut w = plain_weekly();
    w.unsubscribe_url = Some("https://x.test/unsub?t=1".into());
    let (h, t) = (render_html(&w), render_text(&w));
    for out in [&h, &t] {
        assert!(out.contains("/settings/human-review"), "{out}");
        assert!(out.contains("Want an expert to look at this?"), "{out}");
        assert!(!out.contains("harun.dev"));
    }
    let foot = h.find("&middot; opsagent.dev").expect("footer");
    let unsub = h.find("https://x.test/unsub?t=1").expect("unsub");
    assert!(unsub > foot && unsub < foot + h[foot..].find("</table>").expect("end"));
    assert!(t.contains("Unsubscribe: https://x.test/unsub?t=1"));
    w.human_review_url = None;
    w.unsubscribe_url = None;
    let (h, t) = (render_html(&w), render_text(&w));
    for out in [&h, &t] {
        assert!(!out.contains("human-review"), "{out}");
        assert!(!out.contains("nsubscribe"), "{out}");
    }
}

#[test]
fn notice_escapes_and_renders_button() {
    use opsagent_deliver::{render_notice, NoticeEmail};
    let mut n = NoticeEmail {
        preheader: "p".into(),
        heading: "<script>h</script>".into(),
        paragraphs: vec!["<script>p</script>".into()],
        button: Some(("Go now".into(), "https://x.test/go?a=1&b=2".into())),
        footnote: None,
        unsubscribe_url: None,
        code: Some("12<3>45".into()),
    };
    let h = render_notice(&n);
    assert!(
        h.contains("letter-spacing") && h.contains("12&#60;3&#62;45"),
        "{h}"
    );
    assert!(!h.contains("<script>"), "{h}");
    assert!(
        h.contains("Go now") && h.contains("href=\"https://x.test/go?a=1&#38;b=2\""),
        "{h}"
    );
    assert!(h.contains("color-scheme"));
    n.button = None;
    assert!(!render_notice(&n).contains("<a "));
    // The shared layout carries the logo (hosted PNG; mail clients do not render SVG).
    assert!(render_notice(&n).contains(r#"src="https://opsagent.dev/email/logo.png""#));
    if let Ok(dir) = std::env::var("PLAN8_SAMPLES") {
        let mut w = plain_weekly();
        w.unsubscribe_url = Some("https://x.test/unsub".into());
        std::fs::write(format!("{dir}/plan8-weekly.html"), render_html(&w)).unwrap();
        n.heading = "Your AI key expires soon".into();
        n.paragraphs = vec![
            "The Anthropic key for Acme expires on 30 November.".into(),
            "Replace it in settings to keep AI summaries running.".into(),
        ];
        n.button = Some((
            "Open settings".into(),
            "https://opsagent.dev/settings".into(),
        ));
        n.footnote = Some("You get this because you own the account.".into());
        std::fs::write(format!("{dir}/plan8-notice.html"), render_notice(&n)).unwrap();
    }
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
    assert!(!t.contains("rrrr"), "an unknown reason code is left out");
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
    assert!(t.contains("Request a human review"));
    assert!(t.contains("/settings/human-review"));
    assert!(t.contains(LINK_BASE));
}

#[test]
fn untracked_data_leaves_out_its_rows_and_placeholders() {
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
        let low = out.to_lowercase();
        for gone in [
            "spend:",
            "not tracked",
            "untagged",
            "unknown",
            "not recorded",
            "would have done",
            "nothing",
            "$0.00",
        ] {
            assert!(!low.contains(gone), "{name} has {gone:?}: {out}");
        }
        assert!(low.contains("0 open issues"), "{name}: {out}");
    }
}

#[test]
fn weekly_shows_a_row_once_it_has_data() {
    let extras = WeeklyExtras {
        last_restore_test_on: chrono::NaiveDate::from_ymd_opt(2026, 9, 30),
        untagged_spend_pct: Some(12.34),
        would_have_done: vec!["Stop idle instance".into()],
    };
    let f = finding("04", Severity::High, FindingStatus::Open, &[], "no backups");
    let w = build_weekly(&conn(), &[f], None, &extras, now(), LINK_BASE);
    for out in [render_text(&w), render_html(&w)] {
        assert!(out.contains("1 open issue;"), "singular: {out}");
        assert!(out.contains("2026-09-30") && out.contains("12.3%"), "{out}");
        assert!(out.contains("Stop idle instance"), "{out}");
    }
}

#[test]
fn no_dashboard_link_when_the_recipient_cannot_open_it() {
    let mut w = plain_weekly();
    w.link = None;
    w.human_review_url = None;
    w.unsubscribe_url = Some("https://x.test/unsub?t=1".into());
    for out in [render_text(&w), render_html(&w), render_slack(&w)] {
        assert!(!out.contains("/connections/"), "{out}");
        assert!(!out.contains("dashboard"), "{out}");
    }
}

fn health_text(reason: Option<&str>) -> String {
    let mut c = conn();
    c.status = ConnectionStatus::Revoked;
    c.status_reason = reason.map(Into::into);
    let fs = [opened(Severity::High, "open port")];
    render_text(&build_briefing(&c, &fs, since(), now(), LINK_BASE).expect("briefing"))
}

#[test]
fn health_reasons_are_plain_words_and_unknown_codes_are_left_out() {
    for (code, words) in [
        ("access_denied", "AWS refused access to the role"),
        ("account_already_connected", "already connected to another"),
        (
            "external_id_not_enforced",
            "does not require OpsAgent's ExternalId",
        ),
        ("account_mismatch", "different AWS account"),
        ("verify_error:timeout", "could not finish"),
        ("revoked_at_period_end", "end of your billing period"),
    ] {
        let t = health_text(Some(code));
        assert!(t.contains("revoked; ") && t.contains(words), "{t}");
        assert!(!t.contains(code), "raw code shown: {t}");
    }
    for code in [
        "customer_disconnected",
        "organisation_deleted",
        "brand_new_code",
    ] {
        let t = health_text(Some(code));
        assert!(t.contains("*Connection health:* revoked\n"), "{t}");
        assert!(!t.contains(code), "{t}");
    }
    assert!(health_text(None).contains("• High: open port"));
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
