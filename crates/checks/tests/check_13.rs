mod common;
use common::*;
use opsagent_checks::check_13_credentials::CredentialDepth;
use opsagent_core::finding::Severity::*;
use opsagent_core::resource::{Provider, Resource, ResourceKind};
use serde_json::json;

fn user(id: &str, attrs: serde_json::Value) -> Resource {
    Resource {
        provider: Provider::Aws,
        account: "1".into(),
        region: "global".into(),
        kind: ResourceKind::Identity,
        identity: id.into(),
        name: id.into(),
        tags: Default::default(),
        attributes: attrs,
        observed_at: "2026-10-01T00:00:00Z".parse().unwrap(),
    }
}

fn keys(unused: serde_json::Value, active: u8) -> serde_json::Value {
    json!({"service":"iam","access_keys_active":active,"unused_key_age_days":unused,
        "console":false,"console_last_used_days":null,"mfa":true})
}

#[tokio::test]
async fn insecure_exact_set() {
    let (r, c) = load("insecure").await;
    assert_eq!(
        set(&run(&CredentialDepth, &r, &c)),
        vec![
            t("user-stale-pw", "stale_password", Low),
            t("user-two-keys", "two_active_keys", Low),
            t("user-unused-key", "key_never_used", Medium),
        ]
    );
}

#[tokio::test]
async fn clean_is_empty() {
    let (r, c) = load("clean").await;
    assert!(run(&CredentialDepth, &r, &c).is_empty());
}

#[test]
fn never_used_key_boundary_at_seven_days() {
    let rs = [
        user("new", keys(json!(6), 1)),
        user("old", keys(json!(7), 1)),
        user("none", keys(json!(null), 1)),
    ];
    let d = run(&CredentialDepth, &rs, &[]);
    assert_eq!(set(&d), vec![t("old", "key_never_used", Medium)]);
    assert_eq!(d[0].evidence[0].excerpt, "unused_key_age_days=7");
    assert_eq!(
        d[0].next_step,
        "Delete or rotate keys that were never used."
    );
}

#[test]
fn two_active_keys_low_and_one_key_clean() {
    let rs = [
        user("two", keys(json!(null), 2)),
        user("one", keys(json!(null), 1)),
    ];
    assert_eq!(
        set(&run(&CredentialDepth, &rs, &[])),
        vec![t("two", "two_active_keys", Low)]
    );
}

#[test]
fn password_boundary_at_90_days() {
    let pw = |d: u32, console: bool| {
        user(
            "u",
            json!({"service":"iam","access_keys_active":0,"console":console,"console_last_used_days":d}),
        )
    };
    assert!(run(&CredentialDepth, &[pw(90, true)], &[]).is_empty());
    assert_eq!(
        set(&run(&CredentialDepth, &[pw(91, true)], &[])),
        vec![t("u", "stale_password", Low)]
    );
    assert!(run(&CredentialDepth, &[pw(400, false)], &[]).is_empty());
}

#[test]
fn root_is_skipped() {
    let root = user(
        "root",
        json!({"service":"iam","root":true,"access_keys_active":2,"console_last_used_days":400}),
    );
    assert!(run(&CredentialDepth, &[root], &[]).is_empty());
}

#[test]
fn denied_credential_report_is_skipped() {
    let rs = [user("two", keys(json!(30), 2))];
    let mut parts = CtxParts::default();
    parts.unavailable.insert("iam".into());
    assert!(run_with(&parts, &CredentialDepth, &rs, &[]).is_empty());
}
