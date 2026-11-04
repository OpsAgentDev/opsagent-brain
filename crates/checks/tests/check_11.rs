mod common;
use common::*;
use opsagent_checks::check_11_encryption::EncryptionAtRest;
use opsagent_core::finding::Severity::*;
use opsagent_core::resource::{Provider, Resource, ResourceKind};
use serde_json::json;

fn res(id: &str, attrs: serde_json::Value) -> Resource {
    Resource {
        provider: Provider::Aws,
        account: "1".into(),
        region: "r".into(),
        kind: ResourceKind::Storage,
        identity: id.into(),
        name: id.into(),
        tags: Default::default(),
        attributes: attrs,
        observed_at: "2026-10-01T00:00:00Z".parse().unwrap(),
    }
}

#[tokio::test]
async fn insecure_exact_set() {
    let (r, c) = load("insecure").await;
    let mut want = vec![
        t("db-plain", "unencrypted_database", High),
        t("cluster-plain", "unencrypted_database", High),
        t("vol-plain-attached", "unencrypted_volume", Medium),
        t("vol-plain-detached", "unencrypted_volume", Low),
        t("snap-ebs-plain", "unencrypted_snapshot", Low),
        t("snap-rds-plain", "unencrypted_snapshot", Low),
        t("snap-cluster-plain", "unencrypted_snapshot", Low),
    ];
    want.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    assert_eq!(set(&run(&EncryptionAtRest, &r, &c)), want);
}

#[tokio::test]
async fn clean_is_empty() {
    let (r, c) = load("clean").await;
    assert!(run(&EncryptionAtRest, &r, &c).is_empty());
}

#[test]
fn volume_severity_follows_attachment() {
    let rs = [
        res(
            "a",
            json!({"service":"ebs","attached":true,"encrypted":false}),
        ),
        res(
            "b",
            json!({"service":"ebs","attached":false,"encrypted":false}),
        ),
    ];
    let d = run(&EncryptionAtRest, &rs, &[]);
    assert_eq!(
        set(&d),
        vec![
            t("a", "unencrypted_volume", Medium),
            t("b", "unencrypted_volume", Low)
        ]
    );
    assert!(d[0]
        .next_step
        .starts_with("Encryption cannot be switched on in place"));
    assert_eq!(d[0].evidence[0].excerpt, "encrypted=false attached=true");
}

#[test]
fn encrypted_and_unknown_flags_are_skipped() {
    let rs = [
        res("ok", json!({"service":"rds","encrypted":true})),
        res("unknown", json!({"service":"ebs","attached":true})),
        res("null", json!({"service":"rds","encrypted":null})),
        res("other", json!({"service":"s3","encrypted":false})),
    ];
    assert!(run(&EncryptionAtRest, &rs, &[]).is_empty());
}

#[test]
fn unreadable_service_is_skipped_but_others_still_report() {
    let rs = [
        res("snap", json!({"service":"ebs_snapshot","encrypted":false})),
        res(
            "vol",
            json!({"service":"ebs","attached":true,"encrypted":false}),
        ),
    ];
    let mut parts = CtxParts::default();
    parts.unavailable.insert("ebs_snapshot".into());
    assert_eq!(
        set(&run_with(&parts, &EncryptionAtRest, &rs, &[])),
        vec![t("vol", "unencrypted_volume", Medium)]
    );
}

#[test]
fn title_uses_the_name_not_the_arn() {
    let mut r = res(
        "arn:aws:ec2:r:1:volume/vol-1",
        json!({"service":"ebs","attached":true,"encrypted":false}),
    );
    r.name = "data".into();
    let d = run(&EncryptionAtRest, &[r], &[]);
    assert_eq!(d[0].title, "Volume data is not encrypted at rest");
}
