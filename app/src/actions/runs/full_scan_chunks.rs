//! The chunks of one full scan: `service@region` inventory, `simulate`, then `finalize`.
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    panic::{catch_unwind, AssertUnwindSafe},
};

use opsagent_checks::{Check, CheckCtx, MetricStore};
use opsagent_connectors::{
    Connector, Credentials, InventoryResult, Result as ConnResult, Scope, SimulationResult,
};
use opsagent_core::{
    connection::{Connection, Posture},
    finding::FindingDraft,
    resource::{CallCount, Resource},
};
use opsagent_ledger::{ChunkOutcome, LedgerError, Result};
use serde_json::{json, Value};
use uuid::Uuid;

use super::{finding_lifecycle, FullScan};
use crate::{
    actions::uow::Repos,
    workers::common::{classify, lerr, revoked},
};

pub(super) const SIMULATE: &str = "simulate";
pub(super) const FINALIZE: &str = "finalize";

/// Restore simulations per scan; roles past the cap stay unsimulated (check 04: coverage unknown).
const MAX_SIMULATED_ROLES: usize = 20;

/// One `service@region` inventory chunk of a run, written under `fence`.
pub struct Chunk<'a> {
    pub run_id: Uuid,
    pub fence: u64,
    pub organisation_id: Uuid,
    pub connection_id: Uuid,
    pub provider: &'a str,
    pub service: &'a str,
    pub region: &'a str,
}

/// One scan run's fixed inputs, shared by its chunks.
pub(super) struct Scan<'a> {
    pub(super) fs: &'a FullScan,
    pub(super) run_id: Uuid,
    pub(super) c: &'a Connection,
    pub(super) k: &'a dyn Connector,
    pub(super) cr: &'a Credentials,
}

/// Reads checkpoint JSON this process wrote: missing or `Null` is empty, anything else must parse.
fn parse<T: serde::de::DeserializeOwned + Default>(v: &Value) -> Result<T> {
    if v.is_null() {
        return Ok(T::default());
    }
    serde_json::from_value(v.clone()).map_err(|_| LedgerError::Job {
        code: "checkpoint_corrupt".into(),
        retry: false,
    })
}

impl FullScan {
    /// Upserts one chunk's inventory and its `api_call_stats` in one transaction holding the
    /// run fence; safe to re-run for the same run. True when the inventory was partial (a
    /// failed call or `partial_errors`).
    pub async fn store_chunk(
        &self,
        c: Chunk<'_>,
        inv: &ConnResult<InventoryResult>,
    ) -> Result<bool> {
        let tx = self.uow.begin().await.map_err(lerr)?;
        tx.ledger().hold_fence(c.run_id, c.fence).await?;
        // (service, region, outcome) -> count
        let mut calls: BTreeMap<(String, String, &'static str), i64> = BTreeMap::new();
        let partial = match inv {
            Ok(inv) => {
                let (org, conn, now) = (c.organisation_id, c.connection_id, self.clock.now());
                tx.resources()
                    .upsert_chunk(org, conn, c.run_id, &inv.resources, now)
                    .await
                    .map_err(lerr)?;
                calls.insert((c.service.into(), c.region.into(), "ok"), 1);
                for e in &inv.partial_errors {
                    *calls
                        .entry((e.service.clone(), e.region.clone(), "error"))
                        .or_default() += 1;
                }
                !inv.partial_errors.is_empty()
            }
            Err(e) => {
                let (code, _) = classify(e);
                tracing::warn!(code, run = %c.run_id, service = c.service, region = c.region, "inventory chunk failed");
                calls.insert((c.service.into(), c.region.into(), "error"), 1);
                true
            }
        };
        let calls: Vec<CallCount> = calls
            .into_iter()
            .map(|((service, region, outcome), count)| CallCount {
                service,
                region,
                outcome,
                count,
            })
            .collect();
        tx.resources()
            .replace_inventory_calls(c.run_id, c.provider, c.service, c.region, &calls)
            .await
            .map_err(lerr)?;
        tx.commit().await.map_err(lerr)?;
        Ok(partial)
    }
}

impl Scan<'_> {
    pub(super) async fn chunk(&self, chunk: String, fence: u64) -> Result<ChunkOutcome> {
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
    async fn inventory(&self, svc: &str, region: &str, fence: u64) -> Result<ChunkOutcome> {
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
        let partial = self.fs.store_chunk(chunk, &inv).await?;
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
    async fn unavailable(&self, stats: &mut Value, mut down: BTreeSet<String>) -> Result<()> {
        if down.is_empty() {
            return Ok(());
        }
        let so_far = self
            .fs
            .uow
            .ledger()
            .load_run(self.run_id)
            .await?
            .checkpoint
            .stats;
        down.extend(parse::<BTreeSet<String>>(&so_far["unavailable"])?);
        stats["unavailable"] = json!(down);
        Ok(())
    }

    /// Resources observed in this run, as the checks see them.
    async fn seen(&self, repos: &dyn Repos) -> Result<Vec<Resource>> {
        let (c, account) = (self.c, self.c.external_account_id.as_deref());
        repos
            .resources()
            .observed(
                c.organisation_id,
                c.id,
                self.run_id,
                self.k.provider(),
                account.unwrap_or_default(),
            )
            .await
            .map_err(lerr)
    }

    /// Restore simulation for each distinct backup-plan role seen this run, stored in the
    /// checkpoint cursor so a resumed run does not repeat the calls. A failed call leaves its
    /// role out (its finding reads `coverage_unknown`). The run is `partial` (but with no
    /// `partial_reason`, so it still ends `done`): lifecycle must not resolve findings from
    /// checks it could not feed.
    async fn simulate(&self) -> Result<ChunkOutcome> {
        let resources = self.seen(&*self.fs.uow).await?;
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
    async fn finalize(&self, fence: u64) -> Result<ChunkOutcome> {
        let (run_id, c, k) = (self.run_id, self.c, self.k);
        let cp = self.fs.uow.ledger().load_run(run_id).await?.checkpoint;
        let so_far = cp.stats;
        let simulations: HashMap<String, SimulationResult> = parse(&cp.cursor["simulations"])?;
        let unavailable: BTreeSet<String> = parse(&so_far["unavailable"])?;
        let partial = so_far["partial"] == json!(true);
        let now = self.fs.clock.now();
        let cost = k.cost_daily(self.cr, 30).await.unwrap_or_else(|e| {
            // Cost visibility is optional (PRD 7.3): cost checks see no rows.
            let (code, _) = classify(&e);
            tracing::warn!(code, run = %run_id, "full_scan: cost unavailable");
            vec![]
        });
        let tx = self.fs.uow.begin().await.map_err(lerr)?;
        tx.ledger().hold_fence(run_id, fence).await?;
        if !partial {
            let gone = tx
                .resources()
                .mark_unseen_gone(c.organisation_id, c.id, run_id, now);
            gone.await.map_err(lerr)?;
        }
        let resources = self.seen(&*tx).await?;
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
        let (drafts, check_errors) = run_checks(self.fs.checks, k, &cx, run_id);
        finding_lifecycle::apply(&*tx, c, run_id, &drafts, now, partial)
            .await
            .map_err(lerr)?;
        let rows = tx.findings().posture_rows(c.organisation_id, c.id);
        let posture = Posture::from_rows(&rows.await.map_err(lerr)?);
        let mut stats = serde_json::to_value(posture).map_err(lerr)?;
        stats["partial"] = json!(partial);
        stats["check_errors"] = json!(check_errors);
        if so_far["revoked"] == json!(true) {
            stats["partial_reason"] = json!("revoked");
        }
        tx.commit().await.map_err(lerr)?;
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
) -> (Vec<FindingDraft>, Vec<&'static str>) {
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
