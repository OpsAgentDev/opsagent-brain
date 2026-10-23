//! One `full_scan` chunk's inventory: upsert `resources`, write `resource_history`, count
//! `api_call_stats`. One transaction holding the run fence; safe to re-run for the same run.
use std::collections::BTreeMap;

use chrono::Utc;
use opsagent_connectors::{InventoryResult, Result as ConnResult};
use opsagent_core::resource::ResourcesRepo;
use opsagent_ledger::Result;
use sea_orm::{ConnectionTrait, DatabaseConnection, TransactionTrait};
use uuid::Uuid;

use crate::{
    adapters::db::Pg,
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
            Pg::new(&txn)
                .upsert_chunk(
                    c.organisation_id,
                    c.connection_id,
                    c.run_id,
                    &inv.resources,
                    Utc::now(),
                )
                .await
                .map_err(db_err)?;
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
