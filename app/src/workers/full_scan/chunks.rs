//! The chunks of one full scan: `service@region` inventory, `simulate`, then `finalize`.
use crate::adapters::db::ledger_storage::{db_err, hold_fence, stmt, PgStorage};
use std::{
    collections::{BTreeSet, HashMap},
    panic::{catch_unwind, AssertUnwindSafe},
};

use chrono::Utc;
use opsagent_checks::{Check, CheckCtx, MetricStore};
use opsagent_connectors::{Connector, Credentials, Scope, SimulationResult};
use opsagent_core::resource::Resource;
use opsagent_ledger::{ChunkOutcome, LedgerError, Storage};
use sea_orm::{ConnectionTrait, DatabaseConnection, TransactionTrait};
use serde_json::{json, Value};
use uuid::Uuid;

use super::{FINALIZE, SIMULATE};
use crate::{
    models::{_entities::connections, enum_of},
    services::{
        finding_lifecycle,
        inventory_upsert::{self, exec, Chunk},
        posture,
    },
    workers::common::{classify, revoked, LResult},
};

/// One scan run's fixed inputs, shared by its chunks.
pub(super) struct Scan<'a> {
    pub(super) db: &'a DatabaseConnection,
    pub(super) storage: &'a PgStorage,
    pub(super) run_id: Uuid,
    pub(super) c: &'a connections::Model,
    pub(super) k: &'a dyn Connector,
    pub(super) cr: &'a Credentials,
    pub(super) checks: fn() -> Vec<Box<dyn Check>>,
}

/// Reads checkpoint JSON this process wrote: missing or `Null` is empty, anything else must parse.
fn parse<T: serde::de::DeserializeOwned + Default>(v: &Value) -> LResult<T> {
    if v.is_null() {
        return Ok(T::default());
    }
    serde_json::from_value(v.clone()).map_err(|_| LedgerError::Job {
        code: "checkpoint_corrupt".into(),
        retry: false,
    })
}

/// Restore simulations per scan; roles past the cap stay unsimulated (check 04: coverage unknown).
const MAX_SIMULATED_ROLES: usize = 20;

impl Scan<'_> {
    pub(super) async fn chunk(&self, chunk: String, fence: u64) -> LResult<ChunkOutcome> {
        if chunk == FINALIZE {
            return self.finalize(fence).await;
        }
        if chunk == SIMULATE {
            return self.simulate().await;
        }
        let (svc, region) = chunk.rsplit_once('@').ok_or(LedgerError::NotFound)?;
        self.inventory(svc, region, fence).await
    }

    /// One `service@region` chunk: scoped inventory, upserted under the fence.
    async fn inventory(&self, svc: &str, region: &str, fence: u64) -> LResult<ChunkOutcome> {
        let scope = Scope {
            regions: vec![region.into()],
            services: vec![svc.into()],
        };
        let inv = self.k.inventory(self.cr, &scope).await;
        let chunk = Chunk {
            run_id: self.run_id,
            fence,
            organisation_id: self.c.organisation_id,
            connection_id: self.c.id,
            provider: &self.c.provider,
            service: svc,
            region,
        };
        let partial = inventory_upsert::upsert_chunk(self.db, chunk, &inv).await?;
        // Only ever set `partial`, never clear it: chunk stats merge by key. `partial_reason`
        // makes `run_chunked` end the run `Partial`; `revoked` is turned into the reason by
        // `finalize`, so a later chunk cannot overwrite it.
        let mut stats = match &inv {
            Err(e) if revoked(e) => json!({ "partial": true, "revoked": true }),
            _ if partial => json!({ "partial": true, "partial_reason": "partial_inventory" }),
            _ => json!({}),
        };
        let down = match &inv {
            Ok(inv) => inv
                .partial_errors
                .iter()
                .map(|e| e.service.clone())
                .collect(),
            Err(_) => BTreeSet::from([svc.to_owned()]),
        };
        self.unavailable(&mut stats, down).await?;
        Ok(ChunkOutcome {
            stats,
            ..Default::default()
        })
    }

    /// Adds `down` to the run's `stats.unavailable` (the services whose reads failed so far).
    /// Stats merge by key, so the chunk writes the union.
    async fn unavailable(&self, stats: &mut Value, mut down: BTreeSet<String>) -> LResult<()> {
        if down.is_empty() {
            return Ok(());
        }
        let so_far = self.storage.load_run(self.run_id).await?.checkpoint.stats;
        down.extend(parse::<BTreeSet<String>>(&so_far["unavailable"])?);
        stats["unavailable"] = json!(down);
        Ok(())
    }

    /// Restore simulation for each distinct backup-plan role seen this run, stored in the
    /// checkpoint cursor so a resumed run does not repeat the calls. A failed call leaves its
    /// role out (its finding reads `coverage_unknown`). The run is `partial` (but with no
    /// `partial_reason`, so it still ends `done`): lifecycle must not resolve findings from
    /// checks it could not feed.
    async fn simulate(&self) -> LResult<ChunkOutcome> {
        let resources = seen(self.db, self.c, self.k, self.run_id).await?;
        let roles: BTreeSet<&str> = resources
            .iter()
            .filter(|r| r.service() == "backup" && r.attributes["plan"] == true)
            .flat_map(|r| {
                r.attributes["iam_role_arns"]
                    .as_array()
                    .into_iter()
                    .flatten()
            })
            .filter_map(Value::as_str)
            .collect();
        let over_cap = roles.len() > MAX_SIMULATED_ROLES;
        let (mut sims, mut failed_calls) = (serde_json::Map::new(), false);
        for role in roles.into_iter().take(MAX_SIMULATED_ROLES) {
            match self.k.simulate_restore(self.cr, role).await {
                Ok(s) => {
                    sims.insert(role.to_owned(), json!(s));
                }
                Err(e) => {
                    let (code, _) = classify(&e);
                    tracing::warn!(code, run = %self.run_id, "full_scan: restore simulation failed");
                    failed_calls = true;
                }
            }
        }
        let mut stats = json!({});
        if failed_calls || over_cap {
            // Unsimulated roles (failed or past the cap) must not let lifecycle resolve their findings.
            stats["partial"] = json!(true);
        }
        Ok(ChunkOutcome {
            stats,
            cursor: json!({ "simulations": sims }),
        })
    }

    /// Gone-marking, checks, lifecycle and posture, in one fenced transaction.
    async fn finalize(&self, fence: u64) -> LResult<ChunkOutcome> {
        let (db, run_id, c, k) = (self.db, self.run_id, self.c, self.k);
        let cp = self.storage.load_run(run_id).await?.checkpoint;
        let so_far = cp.stats;
        let simulations: HashMap<String, SimulationResult> = parse(&cp.cursor["simulations"])?;
        let unavailable: BTreeSet<String> = parse(&so_far["unavailable"])?;
        let partial = so_far["partial"] == json!(true);
        let now = Utc::now();
        let cost = k.cost_daily(self.cr, 30).await.unwrap_or_else(|e| {
            // Cost visibility is optional (PRD 7.3): cost checks see no rows.
            let (code, _) = classify(&e);
            tracing::warn!(code, run = %run_id, "full_scan: cost unavailable");
            vec![]
        });
        let txn = db.begin().await.map_err(db_err)?;
        hold_fence(&txn, run_id, fence).await?;
        if !partial {
            exec(
                &txn,
                "UPDATE resources r SET gone_at = $3, updated_at = now() \
                 WHERE r.organisation_id = $4 AND r.connection_id = $1 AND r.gone_at IS NULL AND NOT EXISTS \
                 (SELECT 1 FROM resource_history h WHERE h.resource_id = r.id AND h.run_id = $2)",
                vec![c.id.into(), run_id.into(), now.into(), c.organisation_id.into()],
            )
            .await?;
        }
        let resources = seen(&txn, c, k, run_id).await?;
        // Checks read utilisation (CPU, GPU) from inventory attributes; no metric pulls yet.
        let metrics = MetricStore::default();
        let cx = CheckCtx {
            connection_id: c.id,
            resources: &resources,
            cost: &cost,
            metrics: &metrics,
            simulations: &simulations,
            now,
            unavailable: &unavailable,
        };
        let (drafts, check_errors) = run_checks(self.checks, k, &cx, run_id);
        finding_lifecycle::apply(&txn, c, run_id, &drafts, now, partial).await?;
        let mut stats = posture::posture(&txn, c).await?;
        stats["partial"] = json!(partial);
        stats["check_errors"] = json!(check_errors);
        if so_far["revoked"] == json!(true) {
            stats["partial_reason"] = json!("revoked");
        }
        txn.commit().await.map_err(db_err)?;
        Ok(ChunkOutcome {
            stats,
            ..Default::default()
        })
    }
}

/// Runs every check that supports the provider and has its capabilities. A buggy check fails
/// alone (PRD 7.3); its id is returned in the second list.
fn run_checks(
    checks: fn() -> Vec<Box<dyn Check>>,
    k: &dyn Connector,
    cx: &CheckCtx,
    run_id: Uuid,
) -> (Vec<opsagent_core::finding::FindingDraft>, Vec<&'static str>) {
    let (provider, caps) = (k.provider(), k.capabilities());
    let (mut drafts, mut check_errors) = (vec![], vec![]);
    for ch in checks() {
        if !ch.supported().contains(&provider) || !ch.required().iter().all(|r| caps.contains(r)) {
            continue;
        }
        match catch_unwind(AssertUnwindSafe(|| ch.run(cx))) {
            Ok(d) => drafts.extend(d),
            Err(_) => {
                tracing::error!(check_id = ch.id(), run = %run_id, "full_scan: check panicked");
                check_errors.push(ch.id());
            }
        }
    }
    (drafts, check_errors)
}

/// Resources observed in this run, as the checks see them.
async fn seen(
    db: &impl ConnectionTrait,
    c: &connections::Model,
    k: &dyn Connector,
    run_id: Uuid,
) -> LResult<Vec<Resource>> {
    let rows = db
        .query_all_raw(stmt(
            "SELECT r.kind, r.identity, r.name, r.region, r.tags, h.attributes, h.observed_at \
             FROM resources r JOIN resource_history h ON h.resource_id = r.id AND h.run_id = $2 \
             WHERE r.organisation_id = $3 AND r.connection_id = $1 ORDER BY r.identity",
            vec![c.id.into(), run_id.into(), c.organisation_id.into()],
        ))
        .await
        .map_err(db_err)?;
    rows.iter()
        .map(|r| {
            let kind: String = r.try_get("", "kind").map_err(db_err)?;
            let tags: serde_json::Value = r.try_get("", "tags").map_err(db_err)?;
            Ok(Resource {
                provider: k.provider(),
                account: c.external_account_id.clone().unwrap_or_default(),
                region: r
                    .try_get::<Option<String>>("", "region")
                    .map_err(db_err)?
                    .unwrap_or_default(),
                kind: enum_of(&kind).ok_or_else(|| db_err(format!("bad resource kind: {kind}")))?,
                identity: r.try_get("", "identity").map_err(db_err)?,
                name: r
                    .try_get::<Option<String>>("", "name")
                    .map_err(db_err)?
                    .unwrap_or_default(),
                tags: serde_json::from_value(tags).map_err(db_err)?,
                attributes: r.try_get("", "attributes").map_err(db_err)?,
                observed_at: r.try_get("", "observed_at").map_err(db_err)?,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_treats_null_as_empty_and_rejects_corrupt_json() {
        assert!(parse::<BTreeSet<String>>(&Value::Null).unwrap().is_empty());
        assert_eq!(parse::<BTreeSet<String>>(&json!(["a"])).unwrap().len(), 1);
        let e = parse::<BTreeSet<String>>(&json!("oops")).unwrap_err();
        assert!(format!("{e:?}").contains("checkpoint_corrupt"));
    }
}
