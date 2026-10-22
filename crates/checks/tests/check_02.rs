mod common;
use common::*;
use opsagent_checks::check_02_iam::IamHygiene;
use opsagent_core::finding::Severity::*;
use opsagent_core::resource::{Provider, Resource, ResourceKind};

#[tokio::test]
async fn noisy_exact_set() {
    let (r, c) = load("noisy").await;
    let got = set(&run(&IamHygiene, &r, &c));
    assert_eq!(
        got,
        vec![
            t("user-admin", "admin_user", High),
            t("user-stale", "key_over_90d", Medium),
            t("user-stale", "no_mfa", Medium),
        ]
    );
}

#[tokio::test]
async fn clean_is_empty() {
    let (r, c) = load("clean").await;
    assert!(run(&IamHygiene, &r, &c).is_empty());
}

fn root(attrs: serde_json::Value) -> Resource {
    Resource {
        provider: Provider::Aws,
        account: "1".into(),
        region: "global".into(),
        kind: ResourceKind::Identity,
        identity: "root".into(),
        name: "root".into(),
        tags: Default::default(),
        attributes: attrs,
        observed_at: "2026-10-01T00:00:00Z".parse().unwrap(),
    }
}

#[test]
fn root_used_critical_only_when_used() {
    let used = root(
        serde_json::json!({"service":"iam","root":true,"mfa":true,"access_keys_active":0,"console_last_used_days":5}),
    );
    let keys = root(
        serde_json::json!({"service":"iam","root":true,"mfa":true,"access_keys_active":1,"console_last_used_days":400}),
    );
    let quiet = root(
        serde_json::json!({"service":"iam","root":true,"mfa":true,"access_keys_active":0,"console_last_used_days":400}),
    );
    assert_eq!(
        set(&run(&IamHygiene, &[used], &[])),
        vec![t("root", "root_used", Critical)]
    );
    assert_eq!(
        set(&run(&IamHygiene, &[keys], &[])),
        vec![t("root", "root_used", Critical)]
    );
    assert!(run(&IamHygiene, &[quiet], &[]).is_empty());
}
