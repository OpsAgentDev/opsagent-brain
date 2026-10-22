mod common;
use chrono::{DateTime, Utc};
use common::*;
use opsagent_checks::check_07_gpu::GpuAndTraining;
use opsagent_checks::{Check, CheckCtx, MetricStore};
use opsagent_core::finding::{FindingDraft, Severity::*};
use opsagent_core::resource::{Provider, Resource, ResourceKind};
use serde_json::json;
use uuid::Uuid;

fn run_at(rs: &[Resource]) -> Vec<FindingDraft> {
    let metrics = MetricStore::default();
    let now: DateTime<Utc> = "2026-10-01T12:00:00Z".parse().unwrap();
    GpuAndTraining.run(&CheckCtx {
        connection_id: Uuid::nil(),
        resources: rs,
        cost: &[],
        metrics: &metrics,
        simulations: &Default::default(),
        now,
        unavailable: &Default::default(),
    })
}

fn res(id: &str, attrs: serde_json::Value) -> Resource {
    Resource {
        provider: Provider::Aws,
        account: "1".into(),
        region: "r".into(),
        kind: ResourceKind::Compute,
        identity: id.into(),
        name: id.into(),
        tags: Default::default(),
        attributes: attrs,
        observed_at: "2026-10-01T00:00:00Z".parse().unwrap(),
    }
}

fn job(id: &str, started: &str, median: serde_json::Value) -> Resource {
    res(
        id,
        json!({"service":"sagemaker","job":true,"status":"InProgress","started_at":started,"median_runtime_s":median}),
    )
}

fn gpu(id: &str, util: serde_json::Value, state: &str) -> Resource {
    res(
        id,
        json!({"service":"ec2","state":state,"accelerated":true,"gpu_util_24h":util,"monthly_cost_usd":900.0,"secret_note":"TOPSECRET"}),
    )
}

#[tokio::test]
async fn noisy_exact_set() {
    let (r, c) = load("noisy").await;
    let got = set(&run(&GpuAndTraining, &r, &c));
    assert_eq!(
        got,
        vec![
            t("i-gpu", "idle_gpu", High),
            t("job-new", "stuck_training_job", Medium),
            t("job-stuck", "stuck_training_job", Medium),
        ]
    );
}

#[tokio::test]
async fn clean_is_empty() {
    let (r, c) = load("clean").await;
    assert!(run(&GpuAndTraining, &r, &c).is_empty());
}

#[test]
fn idle_gpu_has_cost_and_never_leaks_other_keys() {
    let d = run_at(&[gpu("g", json!(2.0), "running")]);
    assert_eq!(set(&d), vec![t("g", "idle_gpu", High)]);
    assert_eq!(d[0].cost_monthly_usd, Some(900.0));
    let all = format!("{d:?}");
    assert!(!all.contains("TOPSECRET") && !all.contains("secret_note"));
}

#[test]
fn gpu_skips_busy_null_absent_and_stopped() {
    let absent = res(
        "a",
        json!({"service":"ec2","state":"running","accelerated":true}),
    );
    let rs = [
        gpu("busy", json!(5.0), "running"),
        gpu("null", json!(null), "running"),
        gpu("stopped", json!(1.0), "stopped"),
        absent,
    ];
    assert!(run_at(&rs).is_empty());
}

#[test]
fn job_thresholds() {
    // now = 12:00; 10h before = 02:00 started.
    let rs = [
        job("over3x", "2026-10-01T02:00:00Z", json!(3000)), // 36000s > 9000
        job("at2x", "2026-10-01T02:00:00Z", json!(18000)),  // 2x, ok
        job("nomed_old", "2026-09-30T11:00:00Z", json!(null)), // 25h
        job("nomed_new", "2026-09-30T13:00:00Z", json!(null)), // 23h
    ];
    assert_eq!(
        set(&run_at(&rs)),
        vec![
            t("nomed_old", "stuck_training_job", Medium),
            t("over3x", "stuck_training_job", Medium),
        ]
    );
}

#[test]
fn finished_job_not_flagged() {
    let mut j = job("done", "2026-09-01T00:00:00Z", json!(60));
    j.attributes["status"] = json!("Completed");
    assert!(run_at(&[j]).is_empty());
}
