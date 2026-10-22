mod common;
use common::*;
use opsagent_checks::check_06_logging::LoggingGaps;
use opsagent_core::finding::Severity::*;
use opsagent_core::resource::{Provider, Resource, ResourceKind};
use serde_json::{json, Value};

fn res(id: &str, region: &str, attrs: Value) -> Resource {
    Resource {
        provider: Provider::Aws,
        account: "1".into(),
        region: region.into(),
        kind: ResourceKind::Log,
        identity: id.into(),
        name: id.into(),
        tags: Default::default(),
        attributes: attrs,
        observed_at: "2026-10-01T00:00:00Z".parse().unwrap(),
    }
}

fn trail(id: &str, logging: bool, writable: bool) -> Resource {
    res(
        id,
        "r",
        json!({"service":"cloudtrail","logging":logging,"bucket_writable":writable}),
    )
}

#[tokio::test]
async fn noisy_findings() {
    let (r, c) = load("noisy").await;
    let d = run(&LoggingGaps, &r, &c);
    let got = set(&d);
    assert!(got.contains(&t("cloudtrail:noisy", "trail_effectively_off", Critical)));
    assert!(got.contains(&t("guardduty-2", "detection_off:local-2", High)));
    assert!(got.contains(&t("/app/noisy", "no_retention", Low)));
    let lg = d.iter().find(|d| d.key.variant == "no_retention").unwrap();
    assert!((lg.cost_monthly_usd.unwrap() - 1.5).abs() < 1e-9);
    assert!(lg.evidence[0].excerpt.contains("1.50"));
    let dd = d
        .iter()
        .find(|d| d.key.variant.starts_with("detection_off"))
        .unwrap();
    assert!(dd.evidence[0].excerpt.contains("local-2"));
}

#[tokio::test]
async fn clean_is_empty() {
    let (r, c) = load("clean").await;
    assert!(run(&LoggingGaps, &r, &c).is_empty());
}

#[test]
fn not_logging_is_critical() {
    let d = run(&LoggingGaps, &[trail("t", false, true)], &[]);
    assert_eq!(
        set(&d),
        vec![t("cloudtrail:1", "trail_effectively_off", Critical)]
    );
}

#[test]
fn no_trail_resource_at_all() {
    let rs = [res("g", "r", json!({"service":"guardduty","enabled":true}))];
    let d = run(&LoggingGaps, &rs, &[]);
    assert_eq!(
        set(&d),
        vec![t("cloudtrail:1", "trail_effectively_off", Critical)]
    );
}

#[test]
fn one_healthy_trail_among_broken_is_fine() {
    let rs = [
        trail("a", false, true),
        trail("b", true, false),
        trail("c", true, true),
    ];
    assert!(run(&LoggingGaps, &rs, &[]).is_empty());
}

#[test]
fn all_broken_one_finding_lists_trails() {
    let rs = [trail("a", false, true), trail("b", true, false)];
    let d = run(&LoggingGaps, &rs, &[]);
    assert_eq!(d.len(), 1);
    let ex = &d[0].evidence[0].excerpt;
    assert!(ex.contains('a') && ex.contains('b'));
}

#[test]
fn missing_keys_are_skipped() {
    let rs = [
        trail("ok", true, true),
        res("g", "r", json!({"service":"guardduty"})),
        res("l", "r", json!({"service":"logs","stored_bytes":5})),
    ];
    assert!(run(&LoggingGaps, &rs, &[]).is_empty());
}

#[test]
fn absent_stored_bytes_has_no_cost() {
    let rs = [
        trail("ok", true, true),
        res("l", "r", json!({"service":"logs","retention_days":null})),
    ];
    let d = run(&LoggingGaps, &rs, &[]);
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].cost_monthly_usd, None);
    assert_eq!(d[0].evidence[0].excerpt, "retention_days=null");
}

#[test]
fn unavailable_services_are_skipped() {
    let rs = [
        res("g", "r", json!({"service":"guardduty","enabled":false})),
        res("l", "r", json!({"service":"logs","retention_days":null})),
    ];
    let un: std::collections::BTreeSet<String> =
        ["cloudtrail", "guardduty", "logs"].map(String::from).into();
    let parts = CtxParts {
        unavailable: un,
        ..Default::default()
    };
    assert!(run_with(&parts, &LoggingGaps, &rs, &[]).is_empty());
}

const OWN: &str = "arn:aws:cloudtrail:eu-west-1:1:trail/org";
const OTHER: &str = "arn:aws:cloudtrail:eu-west-1:9:trail/org";

fn org(arn: &str, extra: Value) -> Resource {
    let mut a = json!({"service":"cloudtrail","is_organization":true});
    a.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    res(arn, "r", a)
}

#[test]
fn org_trail_owned_here_with_unwritable_bucket_is_critical() {
    let rs = [org(OWN, json!({"logging":true,"bucket_writable":false}))];
    assert_eq!(
        set(&run(&LoggingGaps, &rs, &[])),
        vec![t("cloudtrail:1", "trail_effectively_off", Critical)]
    );
}

#[test]
fn org_trail_of_another_account_ignores_bucket() {
    let rs = [org(OTHER, json!({"logging":true,"bucket_writable":false}))];
    assert!(run(&LoggingGaps, &rs, &[]).is_empty());
}

#[test]
fn org_trail_with_unknown_status_is_present() {
    assert!(run(&LoggingGaps, &[org(OTHER, json!({}))], &[]).is_empty());
}

#[test]
fn non_org_trail_with_unknown_status_is_skipped() {
    let rs = [res("t", "r", json!({"service":"cloudtrail"}))];
    assert!(run(&LoggingGaps, &rs, &[]).is_empty());
}
