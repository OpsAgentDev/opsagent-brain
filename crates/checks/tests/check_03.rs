mod common;
use common::*;
use opsagent_checks::check_03_exposure::PublicExposure;
use opsagent_core::finding::Severity::*;
use opsagent_core::resource::{Provider, Resource, ResourceKind};

#[tokio::test]
async fn noisy_exact_set() {
    let (r, c) = load("noisy").await;
    let got = set(&run(&PublicExposure, &r, &c));
    let mut want = vec![
        t("snap-public", "public_snapshot", Critical),
        t("bucket-open", "bucket_no_bpa", Medium),
        t("sg-ssh", "sg_open_admin_port", Critical),
        t("sg-web", "sg_open_web_on_lb", Info),
        t("sg-db", "sg_open_unused", Low),
    ];
    want.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    assert_eq!(got, want);
}

#[tokio::test]
async fn clean_is_empty() {
    let (r, c) = load("clean").await;
    // sg-ok is a 443-on-LB group, identical to noisy's sg-web: an info finding by spec.
    let d = run(&PublicExposure, &r, &c);
    assert_eq!(set(&d), vec![t("sg-ok", "sg_open_web_on_lb", Info)]);
}

fn res(id: &str, attrs: serde_json::Value) -> Resource {
    Resource {
        provider: Provider::Aws,
        account: "1".into(),
        region: "r".into(),
        kind: ResourceKind::Database,
        identity: id.into(),
        name: id.into(),
        tags: Default::default(),
        attributes: attrs,
        observed_at: "2026-10-01T00:00:00Z".parse().unwrap(),
    }
}

#[test]
fn public_db_and_prefix_bucket() {
    let rs = [
        res(
            "db",
            serde_json::json!({"service":"rds","publicly_accessible":true,"backup_retention_days":1}),
        ),
        res(
            "b",
            serde_json::json!({"service":"s3","block_public_access":false,"public_policy_prefix":"logs/"}),
        ),
    ];
    let d = run(&PublicExposure, &rs, &[]);
    assert_eq!(
        set(&d),
        vec![
            t("b", "bucket_no_bpa", Medium),
            t("db", "public_database", Critical)
        ]
    );
    assert!(d
        .iter()
        .find(|d| d.key.variant == "bucket_no_bpa")
        .unwrap()
        .evidence[0]
        .excerpt
        .contains("logs/"));
}
