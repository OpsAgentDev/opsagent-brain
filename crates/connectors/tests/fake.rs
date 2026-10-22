use opsagent_connectors::{
    aws::AwsOutbound, fake::FakeConnector, Connector, ConnectorError, Credentials, MetricQuery,
    Scope,
};
use opsagent_core::resource::{Provider, ResourceKind};

fn creds(a: &str) -> Credentials {
    Credentials::Fake { account: a.into() }
}

#[tokio::test]
async fn noisy_inventory_has_expected_shapes() {
    let c = FakeConnector::new("noisy").unwrap();
    let inv = c
        .inventory(&creds("noisy"), &Scope::default())
        .await
        .unwrap()
        .resources;
    assert!(inv.len() >= 12);
    assert!(inv
        .iter()
        .all(|r| r.provider == Provider::Fake && r.region.starts_with("local")));
    let svc = |s: &str, f: &dyn Fn(&serde_json::Value) -> bool| {
        inv.iter()
            .filter(|r| r.attributes["service"] == s && f(&r.attributes))
            .count()
    };
    assert_eq!(svc("ebs", &|a| a["attached"] == false), 2);
    assert_eq!(svc("eip", &|a| a["associated"] == false), 1);
    assert_eq!(svc("elb", &|a| a["request_count_7d"] == 0), 1);
    assert_eq!(
        svc("iam", &|a| a["key_age_days"] == 120
            && a["mfa"] == false
            && a["console"] == true),
        1
    );
    assert_eq!(svc("iam", &|a| a["admin"] == true), 1);
    assert_eq!(
        svc("rds", &|a| a["snapshot"] == true && a["public"] == true),
        1
    );
    assert_eq!(svc("s3", &|a| a["block_public_access"] == false), 1);
    assert_eq!(
        svc("sg", &|a| a["open_world_ports"] == serde_json::json!([22])
            && a["attached_to"] == "instance"),
        1
    );
    assert_eq!(
        svc("sg", &|a| a["open_world_ports"] == serde_json::json!([443])
            && a["attached_to"] == "lb"),
        1
    );
    assert_eq!(
        svc("sg", &|a| a["open_world_ports"]
            == serde_json::json!([3306])
            && a["attached_to"] == "none"),
        1
    );
    assert_eq!(
        svc("ec2", &|a| a["cpu_avg_7d"] == 2.0
            && a["state"] == "running"),
        1
    );
    assert_eq!(
        svc("ec2", &|a| a["accelerated"] == true
            && a["cpu_avg_7d"] == 1.0),
        1
    );
    assert_eq!(svc("cloudtrail", &|a| a["logging"] == true), 1);
    assert!(inv.iter().any(|r| r.kind == ResourceKind::Log));
}

#[tokio::test]
async fn noisy_cost_has_30_days_with_spike() {
    let c = FakeConnector::new("noisy").unwrap();
    let rows = c.cost_daily(&creds("noisy"), 30).await.unwrap();
    assert_eq!(rows.len(), 30);
    assert_eq!(rows[27].amount_usd, rows[0].amount_usd * 5.0);
    assert_eq!(c.cost_daily(&creds("noisy"), 7).await.unwrap().len(), 7);
}

#[tokio::test]
async fn clean_is_flat() {
    let c = FakeConnector::new("clean").unwrap();
    let rows = c.cost_daily(&creds("clean"), 30).await.unwrap();
    assert!(rows.iter().all(|r| r.amount_usd == rows[0].amount_usd));
    assert!(!c
        .inventory(&creds("clean"), &Scope::default())
        .await
        .unwrap()
        .resources
        .is_empty());
}

#[tokio::test]
async fn verify_outcomes() {
    let c = FakeConnector::new("blocked").unwrap();
    let v = c.verify(&creds("blocked")).await.unwrap();
    assert_eq!(v.extra_grants, vec!["ec2:TerminateInstances"]);
    assert!(v.assume_with_ok && v.assume_without_denied && v.account_matches);
    assert!(v.missing_grants.is_empty());
    let v = FakeConnector::new("noisy")
        .unwrap()
        .verify(&creds("noisy"))
        .await
        .unwrap();
    assert!(v.extra_grants.is_empty() && v.assume_with_ok);
}

#[tokio::test]
async fn unknown_account_and_registry() {
    assert!(matches!(
        FakeConnector::new("nope"),
        Err(ConnectorError::NotFound)
    ));
    let real = opsagent_connectors::Registry::new(AwsOutbound::default(), false);
    assert!(matches!(real.connector("bogus"), Err(ConnectorError::Unknown(n)) if n == "bogus"));
    assert_eq!(real.connector("aws").unwrap().provider(), Provider::Aws);
    let fake = opsagent_connectors::Registry::new(AwsOutbound::default(), true);
    let c = fake.connector("fake").unwrap();
    assert_eq!(c.provider(), Provider::Fake);
    let q = MetricQuery {
        resource_identity: "x".into(),
        metric: "cpu".into(),
        hours: 24,
    };
    assert!(c.metrics(&creds("noisy"), q).await.unwrap().is_empty());
}

fn days_to(ts: &serde_json::Value) -> i64 {
    let at: chrono::DateTime<chrono::Utc> = ts.as_str().unwrap().parse().unwrap();
    (at - fixture_now()).num_days()
}

fn hours_since(ts: &serde_json::Value) -> i64 {
    let at: chrono::DateTime<chrono::Utc> = ts.as_str().unwrap().parse().unwrap();
    (fixture_now() - at).num_hours()
}

/// Fixture timestamps are relative to the fixtures' `observed_at`.
fn fixture_now() -> chrono::DateTime<chrono::Utc> {
    "2026-10-01T00:00:00Z".parse().unwrap()
}

async fn resources(account: &str) -> Vec<opsagent_core::resource::Resource> {
    FakeConnector::new(account)
        .unwrap()
        .inventory(&creds(account), &Scope::default())
        .await
        .unwrap()
        .resources
}

fn count(
    inv: &[opsagent_core::resource::Resource],
    svc: &str,
    f: impl Fn(&serde_json::Value) -> bool,
) -> usize {
    inv.iter()
        .filter(|r| r.service() == svc && f(&r.attributes))
        .count()
}

#[tokio::test]
async fn noisy_has_every_backup_cert_logging_and_gpu_shape() {
    let inv = resources("noisy").await;
    // Backups: one resource outside any plan, one plan whose last job failed, 1-day retention.
    assert_eq!(count(&inv, "rds", |a| a["in_backup_plan"] == false), 1);
    let failed: Vec<_> = inv
        .iter()
        .filter(|r| r.attributes["plan"] == true && r.attributes["last_job_status"] == "FAILED")
        .collect();
    assert_eq!(failed.len(), 1);
    // The failed plan covers two resources: one failed, one completed.
    let covered = failed[0].attributes["selections"].as_array().unwrap();
    let mut statuses: Vec<_> = inv
        .iter()
        .filter(|r| covered.iter().any(|c| c == r.identity.as_str()))
        .map(|r| r.attributes["backup_last_job_status"].as_str().unwrap())
        .collect();
    statuses.sort_unstable();
    assert_eq!(statuses, ["COMPLETED", "FAILED"]);
    let failed_resources = inv
        .iter()
        .filter(|r| r.service() != "backup" && r.attributes["backup_last_job_status"] == "FAILED")
        .count();
    assert_eq!(failed_resources, 1);
    assert_eq!(count(&inv, "rds", |a| a["backup_retention_days"] == 1), 1);
    assert_eq!(count(&inv, "backup", |a| a["vault"] == true), 1);
    // Certificates.
    let cert = |a: &serde_json::Value| a["not_after"].is_string();
    assert_eq!(
        count(&inv, "acm", |a| cert(a) && days_to(&a["not_after"]) == 5),
        1
    );
    assert_eq!(
        count(&inv, "acm", |a| cert(a)
            && a["renewal_status"] == "FAILED"
            && days_to(&a["not_after"]) == 40),
        1
    );
    assert_eq!(
        count(&inv, "acm", |a| cert(a)
            && a["in_use_by"] == serde_json::json!([])),
        1
    );
    assert_eq!(
        count(&inv, "acm", |a| a["endpoint"].is_string()
            && a["presented_serial"] != a["expected_serial"]),
        1
    );
    // Logging.
    assert_eq!(
        count(&inv, "logs", |a| a["retention_days"].is_null()
            && a["stored_bytes"] == 50_000_000_000u64),
        1
    );
    assert_eq!(
        count(&inv, "cloudtrail", |a| a["logging"] == true
            && a["bucket_writable"] == false),
        1
    );
    let gd: Vec<_> = inv.iter().filter(|r| r.service() == "guardduty").collect();
    assert_eq!(gd.len(), 2);
    assert_ne!(gd[0].region, gd[1].region);
    assert_eq!(
        gd.iter()
            .filter(|r| r.attributes["enabled"] == true)
            .count(),
        1
    );
    // GPU and training.
    assert_eq!(
        count(&inv, "ec2", |a| a["accelerated"] == true
            && a["gpu_util_24h"] == 2.0),
        1
    );
    let job = |median: serde_json::Value| {
        count(&inv, "sagemaker", |a| {
            a["job"] == true
                && a["status"] == "InProgress"
                && hours_since(&a["started_at"]) == 30
                && a["median_runtime_s"] == median
        })
    };
    assert_eq!(job(serde_json::json!(21600)), 1);
    assert_eq!(job(serde_json::Value::Null), 1);
}

#[tokio::test]
async fn clean_has_no_backup_cert_logging_or_gpu_problem() {
    let inv = resources("clean").await;
    assert!(count(&inv, "backup", |a| a["plan"] == true) >= 1);
    assert_eq!(
        count(&inv, "backup", |a| a["plan"] == true
            && a["last_job_status"] != "COMPLETED"),
        0
    );
    assert_eq!(count(&inv, "backup", |a| a["cross_account"] == true), 0);
    assert!(count(&inv, "rds", |a| a["in_backup_plan"] == true) >= 1);
    assert_eq!(count(&inv, "rds", |a| a["in_backup_plan"] != true), 0);
    assert!(inv
        .iter()
        .filter(|r| r.service() != "backup")
        .all(|r| r.attributes["backup_last_job_status"] != "FAILED"));
    assert!(inv
        .iter()
        .filter(|r| r.service() != "backup")
        .all(|r| r.attributes["backup_last_job_status"] != "FAILED"));
    assert_eq!(
        count(&inv, "rds", |a| a["backup_retention_days"]
            .as_u64()
            .unwrap_or(0)
            < 7),
        0
    );
    assert!(count(&inv, "acm", |_| true) >= 1);
    assert_eq!(
        count(&inv, "acm", |a| days_to(&a["not_after"]) < 200
            || a["renewal_status"] != "SUCCESS"
            || a["in_use_by"] == serde_json::json!([])
            || a["endpoint"].is_string()),
        0
    );
    assert!(count(&inv, "logs", |_| true) >= 1);
    assert_eq!(count(&inv, "logs", |a| a["retention_days"].is_null()), 0);
    assert_eq!(
        count(&inv, "cloudtrail", |a| a["logging"] != true
            || a["bucket_writable"] != true),
        0
    );
    assert_eq!(count(&inv, "guardduty", |a| a["enabled"] != true), 0);
    assert_eq!(count(&inv, "ec2", |a| a["accelerated"] == true), 0);
    assert_eq!(count(&inv, "sagemaker", |_| true), 0);
}

#[tokio::test]
async fn fake_simulation_and_metrics_come_from_the_fixture() {
    let noisy = FakeConnector::new("noisy").unwrap();
    let s = noisy
        .simulate_restore(&creds("noisy"), "arn:aws:iam::000000000000:role/backup")
        .await
        .unwrap();
    assert_eq!(s.denied, vec!["kms:CreateGrant"]);
    assert_eq!(s.allowed.len(), 4);
    let clean = FakeConnector::new("clean").unwrap();
    let s = clean
        .simulate_restore(&creds("clean"), "arn:aws:iam::000000000000:role/backup")
        .await
        .unwrap();
    assert!(s.denied.is_empty() && s.unknown.is_empty() && s.allowed.len() == 5);
    let q = MetricQuery {
        resource_identity: "i-gpu".into(),
        metric: "gpu_util_avg".into(),
        hours: 24,
    };
    let p = noisy.metrics(&creds("noisy"), q).await.unwrap();
    assert!(!p.is_empty() && p.iter().all(|x| x.value == 2.0));
}

#[tokio::test]
async fn new_services_are_scopable() {
    let c = FakeConnector::new("noisy").unwrap();
    for svc in ["backup", "acm", "logs", "sagemaker"] {
        let scope = Scope {
            regions: vec![],
            services: vec![svc.into()],
        };
        let inv = c
            .inventory(&creds("noisy"), &scope)
            .await
            .unwrap()
            .resources;
        assert!(
            !inv.is_empty() && inv.iter().all(|r| r.service() == svc),
            "{svc}"
        );
    }
}
