mod common;
use chrono::{DateTime, Utc};
use common::*;
use opsagent_checks::check_05_certificates::Certificates;
use opsagent_checks::{CheckCtx, MetricStore};
use opsagent_core::finding::{FindingDraft, Severity::*};
use opsagent_core::resource::{Provider, Resource, ResourceKind};
use serde_json::json;
use uuid::Uuid;

fn res(id: &str, attrs: serde_json::Value) -> Resource {
    Resource {
        provider: Provider::Aws,
        account: "1".into(),
        region: "r".into(),
        kind: ResourceKind::Certificate,
        identity: id.into(),
        name: id.into(),
        tags: Default::default(),
        attributes: attrs,
        observed_at: "2026-10-01T00:00:00Z".parse().unwrap(),
    }
}

/// One managed cert expiring `days` after now (2026-10-01T12:00:00Z).
fn cert(id: &str, not_after: &str, renewal: &str, in_use: &[&str], managed: bool) -> Resource {
    res(
        id,
        json!({"service":"acm","not_after":not_after,"renewal_status":renewal,"in_use_by":in_use,"managed":managed}),
    )
}

fn run_noon(rs: &[Resource]) -> Vec<FindingDraft> {
    let m = MetricStore::default();
    let now: DateTime<Utc> = "2026-10-01T12:00:00Z".parse().unwrap();
    let ctx = CheckCtx {
        connection_id: Uuid::nil(),
        resources: rs,
        cost: &[],
        metrics: &m,
        now,
    };
    let out = opsagent_checks::Check::run(&Certificates, &ctx);
    assert!(out
        .iter()
        .all(|d| !d.evidence.is_empty() && !d.next_step.is_empty()));
    out
}

#[tokio::test]
async fn noisy_exact_set() {
    let (r, c) = load("noisy").await;
    let got = set(&run(&Certificates, &r, &c));
    let mut want = vec![
        t("cert-expiring", "certificate", Critical),
        t("cert-renewal-failed", "certificate", High),
        t("cert-unattached", "certificate", Info),
        t("endpoint:api.noisy.example:443", "certificate", Medium),
    ];
    want.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    assert_eq!(got, want);
}

#[tokio::test]
async fn clean_is_empty() {
    let (r, c) = load("clean").await;
    assert!(run(&Certificates, &r, &c).is_empty());
}

#[test]
fn expires_30d_high() {
    let d = run_noon(&[cert("c", "2026-10-20T00:00:00Z", "SUCCESS", &["lb"], true)]);
    assert_eq!(set(&d), vec![t("c", "certificate", High)]);
}

#[test]
fn renewal_failed_with_5_days_is_critical_and_lists_both() {
    let d = run_noon(&[cert("c", "2026-10-06T12:00:00Z", "FAILED", &["lb"], true)]);
    assert_eq!(set(&d), vec![t("c", "certificate", Critical)]);
    let ex = &d[0].evidence[0].excerpt;
    assert!(ex.contains("FAILED") && ex.contains("days_left=5"), "{ex}");
}

#[test]
fn unattached_and_expiring_reports_expiry() {
    let d = run_noon(&[cert("c", "2026-10-05T00:00:00Z", "SUCCESS", &[], true)]);
    assert_eq!(set(&d), vec![t("c", "certificate", Critical)]);
    assert!(d[0].evidence[0].excerpt.contains("in_use_by=[]"));
}

#[test]
fn imported_cert_judged_on_expiry_only() {
    let d = run_noon(&[
        res(
            "far",
            json!({"service":"acm","not_after":"2027-10-01T00:00:00Z","in_use_by":["lb"],"managed":false}),
        ),
        res(
            "soon",
            json!({"service":"acm","not_after":"2026-10-05T00:00:00Z","in_use_by":["lb"],"managed":false}),
        ),
    ]);
    assert_eq!(set(&d), vec![t("soon", "certificate", Critical)]);
}

#[test]
fn key_stable_while_severity_rises() {
    let at = |na| run_noon(&[cert("c", na, "SUCCESS", &["lb"], true)]);
    let (a, b) = (at("2026-10-26T12:00:00Z"), at("2026-10-06T12:00:00Z"));
    assert_eq!(a[0].key, b[0].key);
    assert_eq!((a[0].severity, b[0].severity), (High, Critical));
}

#[test]
fn expired_is_critical_with_title() {
    let d = run_noon(&[cert("c", "2026-09-28T12:00:00Z", "SUCCESS", &["lb"], true)]);
    assert_eq!(set(&d), vec![t("c", "certificate", Critical)]);
    assert!(d[0].title.contains("expired 3 days ago"), "{}", d[0].title);
}

#[test]
fn renewal_failed_with_20_days_is_high() {
    let d = run_noon(&[cert("c", "2026-10-21T12:00:00Z", "FAILED", &["lb"], true)]);
    assert_eq!(set(&d), vec![t("c", "certificate", High)]);
    assert!(d[0].title.contains("managed renewal failed"));
}
