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
        .all(|r| r.provider == Provider::Fake && r.region == "local"));
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
