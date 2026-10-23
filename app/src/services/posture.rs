//! Posture score of a connection (checks.md).
use crate::adapters::db::ledger_storage::{db_err, stmt};
use std::collections::BTreeMap;

use opsagent_core::finding::Severity;
use opsagent_ledger::Result;
use sea_orm::{ConnectionTrait, Value};
use serde_json::{json, Value as Json};

use crate::models::{_entities::connections, enum_of, enum_str};

/// Posture score per checks.md: `max(0, 100 − Σ weight(open))`; accepted, snoozed and flapping
/// are excluded by counting `open` only.
pub async fn posture(db: &impl ConnectionTrait, c: &connections::Model) -> Result<Json> {
    let rows = db
        .query_all_raw(stmt(
            "SELECT severity, count(*) AS n FROM findings WHERE organisation_id = $2 AND connection_id = $1 \
             AND status = 'open' GROUP BY severity",
            vec![Value::from(c.id), Value::from(c.organisation_id)],
        ))
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
        let s: String = r.try_get("", "severity").map_err(db_err)?;
        let n: i64 = r.try_get("", "n").map_err(db_err)?;
        sum += enum_of(&s).map_or(0.0, Severity::weight) * n as f32;
        counts.insert(s, n);
    }
    Ok(json!({ "score": f64::from((100.0 - sum).max(0.0)), "counts_by_severity": counts }))
}
