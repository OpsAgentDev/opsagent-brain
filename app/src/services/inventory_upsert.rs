//! One `full_scan` chunk's inventory: upsert `resources`, write `resource_history`, count
//! `api_call_stats`. One transaction holding the run fence; safe to re-run for the same run.
use std::collections::BTreeMap;

use opsagent_connectors::{InventoryResult, Result as ConnResult};
use opsagent_ledger::{LedgerError, Result};
use sea_orm::{ConnectionTrait, DatabaseConnection, TransactionTrait};
use serde_json::json;
use uuid::Uuid;

use crate::{
    models::ledger_storage::{db_err, hold_fence, stmt},
    workers::common::classify,
};

pub struct Chunk<'a> {
    pub run_id: Uuid,
    pub fence: u64,
    pub organisation_id: Uuid,
    pub connection_id: Uuid,
    pub provider: &'a str,
    pub service: &'a str,
    pub region: &'a str,
}

// shortcut: ~56 lines, one fenced transaction; split the stats write out when a second job writes api_call_stats.
/// Returns `true` when the chunk's inventory was partial (a failed call or `partial_errors`).
pub async fn upsert_chunk(
    db: &DatabaseConnection,
    c: Chunk<'_>,
    inv: &ConnResult<InventoryResult>,
) -> Result<bool> {
    let txn = db.begin().await.map_err(db_err)?;
    hold_fence(&txn, c.run_id, c.fence).await?;
    // (service, region, outcome) -> count
    let mut stats: BTreeMap<(String, String, &str), i64> = BTreeMap::new();
    let partial = match inv {
        Ok(inv) => {
            for r in &inv.resources {
                upsert_resource(&txn, &c, r).await?;
            }
            stats.insert((c.service.into(), c.region.into(), "ok"), 1);
            for e in &inv.partial_errors {
                *stats
                    .entry((e.service.clone(), e.region.clone(), "error"))
                    .or_default() += 1;
            }
            !inv.partial_errors.is_empty()
        }
        Err(e) => {
            let (code, _) = classify(e);
            tracing::warn!(code, run = %c.run_id, service = c.service, region = c.region, "inventory chunk failed");
            stats.insert((c.service.into(), c.region.into(), "error"), 1);
            true
        }
    };
    // Replace, not add: a re-run chunk restates this run's counts.
    exec(
        &txn,
        "DELETE FROM api_call_stats WHERE run_id = $1 AND action = 'inventory' AND service = $2 AND region = $3",
        vec![c.run_id.into(), c.service.into(), c.region.into()],
    )
    .await?;
    for ((service, region, outcome), count) in stats {
        exec(
            &txn,
            "INSERT INTO api_call_stats (id, run_id, provider, service, action, region, outcome, count) \
             VALUES ($1, $2, $3, $4, 'inventory', $5, $6, $7)",
            vec![
                Uuid::now_v7().into(),
                c.run_id.into(),
                c.provider.into(),
                service.into(),
                region.into(),
                outcome.into(),
                count.into(),
            ],
        )
        .await?;
    }
    txn.commit().await.map_err(db_err)?;
    Ok(partial)
}

async fn upsert_resource(
    txn: &impl ConnectionTrait,
    c: &Chunk<'_>,
    r: &opsagent_core::resource::Resource,
) -> Result<()> {
    let row = txn
        .query_one_raw(stmt(
            "INSERT INTO resources (id, organisation_id, connection_id, kind, identity, name, region, tags, attributes) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (connection_id, identity) DO UPDATE SET kind = EXCLUDED.kind, name = EXCLUDED.name, \
             region = EXCLUDED.region, tags = EXCLUDED.tags, attributes = EXCLUDED.attributes, \
             last_seen_at = now(), gone_at = NULL, updated_at = now() \
             RETURNING id",
            vec![
                Uuid::now_v7().into(),
                c.organisation_id.into(),
                c.connection_id.into(),
                r.kind.to_string().into(),
                r.identity.clone().into(),
                r.name.clone().into(),
                r.region.clone().into(),
                json!(r.tags).into(),
                r.attributes.clone().into(),
            ],
        ))
        .await
        .map_err(db_err)?
        .ok_or(LedgerError::NotFound)?;
    let id: Uuid = row.try_get("", "id").map_err(db_err)?;
    exec(
        txn,
        "INSERT INTO resource_history (id, resource_id, run_id, attributes, observed_at) \
         SELECT $1, $2, $3, $4, $5 WHERE NOT EXISTS \
         (SELECT 1 FROM resource_history WHERE resource_id = $2 AND run_id = $3)",
        vec![
            Uuid::now_v7().into(),
            id.into(),
            c.run_id.into(),
            r.attributes.clone().into(),
            r.observed_at.into(),
        ],
    )
    .await
}

pub(crate) async fn exec(
    db: &impl ConnectionTrait,
    sql: &str,
    values: Vec<sea_orm::Value>,
) -> Result<()> {
    db.execute_raw(stmt(sql, values))
        .await
        .map(|_| ())
        .map_err(db_err)
}
