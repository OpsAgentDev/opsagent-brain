#![allow(dead_code)]
use chrono::{DateTime, Utc};
use opsagent_checks::{Check, CheckCtx, MetricStore};
use opsagent_connectors::{fake::FakeConnector, Connector, CostRow, Credentials, Scope};
use opsagent_core::finding::{FindingDraft, Severity};
use opsagent_core::resource::Resource;
use uuid::Uuid;

pub async fn load(account: &str) -> (Vec<Resource>, Vec<CostRow>) {
    let c = FakeConnector::new(account).unwrap();
    let creds = Credentials::Fake {
        account: account.into(),
    };
    let inv = c.inventory(&creds, &Scope::default()).await.unwrap();
    (inv.resources, c.cost_daily(&creds, 30).await.unwrap())
}

pub fn run(check: &dyn Check, resources: &[Resource], cost: &[CostRow]) -> Vec<FindingDraft> {
    let metrics = MetricStore::default();
    let now: DateTime<Utc> = "2026-10-01T00:00:00Z".parse().unwrap();
    let ctx = CheckCtx {
        connection_id: Uuid::nil(),
        resources,
        cost,
        metrics: &metrics,
        now,
    };
    let out = check.run(&ctx);
    for d in &out {
        assert!(!d.evidence.is_empty(), "{:?}", d.key);
        assert!(!d.next_step.is_empty(), "{:?}", d.key);
        assert_eq!(d.key.check_id, check.id());
    }
    out
}

/// (identity, variant, severity) sorted.
pub fn set(d: &[FindingDraft]) -> Vec<(String, String, Severity)> {
    let mut v: Vec<_> = d
        .iter()
        .map(|d| {
            (
                d.key.resource_identity.clone(),
                d.key.variant.clone(),
                d.severity,
            )
        })
        .collect();
    v.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    v
}

pub fn t(i: &str, v: &str, s: Severity) -> (String, String, Severity) {
    (i.into(), v.into(), s)
}
