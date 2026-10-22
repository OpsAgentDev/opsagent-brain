use chrono::{DateTime, Utc};
use opsagent_connectors::{Capability, CostRow, MetricPoint};
use opsagent_core::finding::FindingDraft;
use opsagent_core::resource::{Provider, Resource};
use std::collections::HashMap;
use uuid::Uuid;

/// Metric series keyed by (resource identity, metric name).
#[derive(Debug, Default, Clone)]
pub struct MetricStore(pub HashMap<(String, String), Vec<MetricPoint>>);

impl MetricStore {
    pub fn get(&self, identity: &str, metric: &str) -> &[MetricPoint] {
        self.0
            .get(&(identity.to_owned(), metric.to_owned()))
            .map_or(&[], Vec::as_slice)
    }
}

pub struct CheckCtx<'a> {
    pub connection_id: Uuid,
    pub resources: &'a [Resource],
    pub cost: &'a [CostRow],
    pub metrics: &'a MetricStore,
    pub now: DateTime<Utc>,
}

pub trait Check {
    fn id(&self) -> &'static str;
    fn supported(&self) -> &[Provider];
    fn required(&self) -> &[Capability];
    fn run(&self, ctx: &CheckCtx) -> Vec<FindingDraft>;
}

/// Shared helpers for checks.
pub(crate) fn svc(r: &Resource) -> &str {
    r.attributes["service"].as_str().unwrap_or("")
}

pub(crate) fn draft(
    ctx: &CheckCtx,
    check_id: &str,
    r: &Resource,
    variant: &str,
    severity: opsagent_core::finding::Severity,
    (title, summary, next_step): (String, String, &str),
    excerpt: String,
) -> FindingDraft {
    use opsagent_core::finding::{Evidence, FindingKey};
    FindingDraft {
        key: FindingKey {
            connection_id: ctx.connection_id,
            check_id: check_id.into(),
            resource_identity: r.identity.clone(),
            variant: variant.into(),
        },
        severity,
        title,
        summary,
        next_step: next_step.into(),
        cost_monthly_usd: r.attributes["monthly_cost_usd"].as_f64(),
        evidence: vec![Evidence {
            source: format!("{}:{}", svc(r), r.identity),
            excerpt,
        }],
    }
}
