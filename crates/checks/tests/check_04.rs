mod common;
use common::*;
use opsagent_checks::check_04_backups::Backups;
use opsagent_checks::{Check, CheckCtx, MetricStore};
use opsagent_connectors::SimulationResult;
use opsagent_core::finding::{FindingDraft, Severity::*};
use opsagent_core::resource::{Provider, Resource, ResourceKind};
use std::collections::HashMap;
use uuid::Uuid;

const ROLE: &str = "arn:aws:iam::000000000000:role/backup";

fn sim(denied: &[&str], unknown: &[&str]) -> HashMap<String, SimulationResult> {
    let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect();
    HashMap::from([(
        ROLE.to_string(),
        SimulationResult {
            allowed: if unknown.is_empty() {
                vec!["kms:Decrypt".into()]
            } else {
                vec![]
            },
            denied: v(denied),
            unknown: v(unknown),
        },
    )])
}

fn go(rs: &[Resource], sims: &HashMap<String, SimulationResult>) -> Vec<FindingDraft> {
    let m = MetricStore::default();
    let ctx = CheckCtx {
        connection_id: Uuid::nil(),
        resources: rs,
        cost: &[],
        metrics: &m,
        simulations: sims,
        now: "2026-10-01T12:00:00Z".parse().unwrap(),
    };
    let out = Backups.run(&ctx);
    for d in &out {
        assert!(
            !d.evidence.is_empty() && !d.next_step.is_empty(),
            "{:?}",
            d.key
        );
    }
    out
}

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
async fn noisy_exact_set() {
    let (r, _) = load("noisy").await;
    let got = set(&go(&r, &sim(&["kms:CreateGrant"], &[])));
    let mut want = vec![
        t("db-orphan", "not_in_plan", Medium),
        t("db-main", "last_job_failed", High),
        t("db-short", "retention_1d", Medium),
        t("plan-nightly", "restore_perms_missing", High),
        t("plan-weekly", "restore_perms_missing", High),
    ];
    want.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    assert_eq!(got, want);
}

#[tokio::test]
async fn failed_plan_flags_only_failed_resource() {
    let (r, _) = load("noisy").await;
    let out = go(&r, &sim(&[], &[]));
    let failed: Vec<_> = out
        .iter()
        .filter(|d| d.key.variant == "last_job_failed")
        .collect();
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].key.resource_identity, "db-main");
    assert!(out.iter().all(|d| d.key.resource_identity != "vol-used"));
}

#[tokio::test]
async fn restore_evidence_lists_denied_actions() {
    let (r, _) = load("noisy").await;
    let out = go(&r, &sim(&["kms:CreateGrant"], &[]));
    let d = out
        .iter()
        .find(|d| d.key.variant == "restore_perms_missing")
        .unwrap();
    assert!(d.evidence[0].excerpt.contains("kms:CreateGrant"));
}

#[tokio::test]
async fn clean_is_empty() {
    let (r, _) = load("clean").await;
    assert!(go(&r, &sim(&[], &[])).is_empty());
}

#[test]
fn unknown_or_missing_simulation_is_coverage_unknown() {
    let plan = res(
        "p",
        serde_json::json!({"service":"backup","plan":true,"iam_role_arns":[ROLE]}),
    );
    let all_unknown = go(std::slice::from_ref(&plan), &sim(&[], &["kms:CreateGrant"]));
    assert_eq!(set(&all_unknown), vec![t("p", "coverage_unknown", Info)]);
    let missing = go(&[plan], &HashMap::new());
    assert_eq!(set(&missing), vec![t("p", "coverage_unknown", Info)]);
}

#[test]
fn cross_account_vault_is_coverage_unknown() {
    let v = res(
        "v",
        serde_json::json!({"service":"backup","vault":true,"cross_account":true}),
    );
    assert_eq!(
        set(&go(&[v], &HashMap::new())),
        vec![t("v", "coverage_unknown", Info)]
    );
}

#[test]
fn missing_in_backup_plan_key_is_skipped() {
    let e = res("i-1", serde_json::json!({"service":"ec2"}));
    assert!(go(&[e], &HashMap::new()).is_empty());
}
