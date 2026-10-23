//! Posture score of a connection (checks.md).
use crate::adapters::db::ledger_storage::db_err;
use std::collections::BTreeMap;

use opsagent_core::finding::{FindingsRepo, Severity};
use opsagent_ledger::Result;
use sea_orm::ConnectionTrait;
use serde_json::{json, Value as Json};

use crate::{
    adapters::db::Pg,
    models::{_entities::connections, enum_str},
};

/// Posture score per checks.md: `max(0, 100 − Σ weight(open))`; accepted, snoozed and flapping
/// are excluded by counting `open` only.
pub async fn posture(db: &impl ConnectionTrait, c: &connections::Model) -> Result<Json> {
    let rows = Pg::new(db)
        .posture_rows(c.organisation_id, c.id)
        .await
        .map_err(db_err)?;
    let mut counts: BTreeMap<String, i64> = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ]
    .into_iter()
    .map(|s| (enum_str(s), 0))
    .collect();
    let mut sum = 0f32;
    for r in rows {
        let n = r.open as i64;
        sum += r.severity.weight() * n as f32;
        *counts.entry(enum_str(r.severity)).or_default() += n;
    }
    Ok(json!({ "score": f64::from((100.0 - sum).max(0.0)), "counts_by_severity": counts }))
}
