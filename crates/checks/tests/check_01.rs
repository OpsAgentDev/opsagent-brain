mod common;
use common::*;
use opsagent_checks::check_01_cost::CostAndIdle;
use opsagent_core::finding::Severity::*;

#[tokio::test]
async fn noisy_exact_set() {
    let (r, c) = load("noisy").await;
    let got = set(&run(&CostAndIdle, &r, &c));
    let mut want = vec![
        t("eip-free", "unassociated_address", Low),
        t("elb-idle", "idle_load_balancer", Low),
        t("i-gpu", "idle_instance", High),
        t("i-idle", "idle_instance", Medium),
        t("vol-orphan-1", "unattached_volume", Low),
        t("vol-orphan-2", "unattached_volume", Low),
        t("cost:2026-09-28", "cost_anomaly", High),
    ];
    want.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    assert_eq!(got, want);
}

#[tokio::test]
async fn anomaly_evidence_and_cost() {
    let (r, c) = load("noisy").await;
    let d = run(&CostAndIdle, &r, &c);
    let a = d.iter().find(|d| d.key.variant == "cost_anomaly").unwrap();
    let e = &a.evidence[0].excerpt;
    assert!(
        e.contains("2026-09-28") && e.contains("500") && e.contains("100"),
        "{e}"
    );
    let g = d
        .iter()
        .find(|d| d.key.resource_identity == "i-gpu")
        .unwrap();
    assert_eq!(g.cost_monthly_usd, Some(900.0));
}

#[tokio::test]
async fn anomaly_ignores_last_two_days() {
    let (r, mut c) = load("noisy").await;
    c[27].amount_usd = 100.0;
    c[29].amount_usd = 500.0;
    let d = run(&CostAndIdle, &r, &c);
    assert!(d.iter().all(|d| d.key.variant != "cost_anomaly"));
}

#[tokio::test]
async fn clean_is_empty() {
    let (r, c) = load("clean").await;
    assert!(run(&CostAndIdle, &r, &c).is_empty());
}

#[tokio::test]
async fn flat_series_no_anomaly_single_spike_yes() {
    let (r, mut c) = load("clean").await;
    for x in c.iter_mut() {
        x.amount_usd = 33.33;
    }
    assert!(run(&CostAndIdle, &r, &c).is_empty());
    c[25].amount_usd = 33.33 * 5.0;
    let d = run(&CostAndIdle, &r, &c);
    assert_eq!(set(&d), vec![t("cost:2026-09-26", "cost_anomaly", High)]);
}
