//! `full_scan` job (PRD 7.3, jobs.md): one chunk per service × region, then a `finalize` chunk
//! that marks unseen resources gone, runs the checks and applies the finding lifecycle.
use std::{
    collections::BTreeSet,
    panic::{catch_unwind, AssertUnwindSafe},
    time::Duration,
};

use async_trait::async_trait;
use chrono::Utc;
use loco_rs::{app::AppContext, bgworker::BackgroundWorker, Result};
use opsagent_checks::{Check, CheckCtx, MetricStore};
use opsagent_connectors::{registry as providers, CallContext, Connector, Credentials, Scope};
use opsagent_core::{connection::ConnectionStatus as S, resource::Resource, run::RunStatus};
use opsagent_ledger::{lease, run_chunked, ChunkOutcome, LedgerError, RunChunkedOptions, Storage};
use sea_orm::{ConnectionTrait, EntityTrait, TransactionTrait};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use super::common::{connector_for, err, lerr, redis_client, LResult};
use crate::{
    app::kek,
    models::{
        _entities::connections,
        connections::{load_creds, status_of},
        ledger_storage::{db_err, hold_fence, stmt, PgStorage},
    },
    services::{
        finding_lifecycle,
        inventory_upsert::{self, exec, Chunk},
    },
};

pub const JOB: &str = "full_scan";
const FINALIZE: &str = "finalize";
const TIME_CAP: Duration = Duration::from_secs(6 * 3600);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullScanArgs {
    pub run_id: Uuid,
}

pub struct FullScanWorker {
    ctx: AppContext,
}

#[async_trait]
impl BackgroundWorker<FullScanArgs> for FullScanWorker {
    fn build(ctx: &AppContext) -> Self {
        Self { ctx: ctx.clone() }
    }

    async fn perform(&self, args: FullScanArgs) -> Result<()> {
        let k = connector_for(&self.ctx, args.run_id).await?;
        let opts = RunChunkedOptions {
            worker_id: format!("{JOB}-{}", Uuid::new_v4()),
            time_cap: TIME_CAP,
            ..Default::default()
        };
        match scan(&self.ctx, args.run_id, k.as_ref(), opts).await {
            // Another worker holds or took over the run; it decides the outcome.
            Ok(_) | Err(LedgerError::LeaseHeld | LedgerError::StaleFence) => Ok(()),
            Err(e) => Err(err(e)),
        }
    }
}

fn service(r: &Resource) -> &str {
    r.attributes["service"].as_str().unwrap_or("")
}

/// Runs (or resumes) the scan for `run_id` with connector `k`. The run row must exist.
pub async fn scan(
    ctx: &AppContext,
    run_id: Uuid,
    k: &dyn Connector,
    opts: RunChunkedOptions,
) -> LResult<RunStatus> {
    scan_with(ctx, run_id, k, opts, opsagent_checks::all).await
}

/// `scan` with an explicit check set (tests inject faulty checks).
pub async fn scan_with(
    ctx: &AppContext,
    run_id: Uuid,
    k: &dyn Connector,
    opts: RunChunkedOptions,
    checks: fn() -> Vec<Box<dyn Check>>,
) -> LResult<RunStatus> {
    let storage = PgStorage::new(ctx.db.clone());
    let run = storage.load_run(run_id).await?;
    if !matches!(run.status, RunStatus::Queued | RunStatus::Running) {
        return Ok(run.status); // duplicate delivery of a finished run
    }
    let db = &ctx.db;
    let conn_id = run.key.connection_id.ok_or(LedgerError::NotFound)?;
    let c = connections::Entity::find_by_id(conn_id)
        .one(db)
        .await
        .map_err(lerr)?
        .ok_or(LedgerError::NotFound)?;
    if !matches!(status_of(&c).map_err(lerr)?, S::Connected | S::Degraded) {
        let redis = redis_client(ctx).map_err(lerr)?;
        let l = lease::acquire(&storage, &redis, run_id, &opts.worker_id, opts.lease_ttl)
            .await?
            .ok_or(LedgerError::LeaseHeld)?;
        let reason = Some(format!("status:{}", c.status));
        let res = storage
            .set_status(run_id, l.fence, RunStatus::Skipped, reason)
            .await;
        lease::release(&redis, &l).await;
        return res.map(|()| RunStatus::Skipped);
    }
    let kek = kek(ctx).map_err(lerr)?;
    let creds = load_creds(db, kek.as_ref(), &c).await.map_err(lerr)?;
    let context = CallContext {
        organisation_id: c.organisation_id,
        run_id,
        trigger: JOB.into(),
    };
    let cr = providers::credentials(&c.provider, &creds, context).map_err(lerr)?;
    let redis = redis_client(ctx).map_err(lerr)?;

    // shortcut: chunks come from an unscoped inventory call on every (re)start, which doubles
    // the AWS calls; upgrade to a declared connector scope when the AWS connector exposes one.
    let inv = k.inventory(&cr, &Scope::default()).await.map_err(lerr)?;
    let mut chunks: Vec<String> = inv
        .resources
        .iter()
        .map(|r| (service(r), r.region.as_str()))
        .chain(
            inv.partial_errors
                .iter()
                .map(|e| (e.service.as_str(), e.region.as_str())),
        )
        .map(|(s, r)| format!("{s}@{r}"))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    chunks.push(FINALIZE.into());

    let (storage, cr, c) = (&storage, &cr, &c);
    run_chunked(
        storage,
        &redis,
        run_id,
        chunks,
        opts,
        |chunk, lease| async move {
            if chunk == FINALIZE {
                return finalize(db, storage, run_id, lease.fence, c, k, cr, checks).await;
            }
            let (svc, region) = chunk.rsplit_once('@').ok_or(LedgerError::NotFound)?;
            let scope = Scope {
                regions: vec![region.into()],
                services: vec![svc.into()],
            };
            let inv = k.inventory(cr, &scope).await;
            let chunk = Chunk {
                run_id,
                fence: lease.fence,
                organisation_id: c.organisation_id,
                connection_id: c.id,
                provider: &c.provider,
                service: svc,
                region,
            };
            let partial = inventory_upsert::upsert_chunk(db, chunk, &inv).await?;
            // Only ever set `partial`, never clear it: chunk stats merge by key. `partial_reason`
            // makes `run_chunked` end the run `Partial`.
            let stats = if partial {
                json!({ "partial": true, "partial_reason": "partial_inventory" })
            } else {
                json!({})
            };
            Ok(ChunkOutcome { stats })
        },
    )
    .await
}

/// Gone-marking, checks, lifecycle and posture, in one fenced transaction.
#[allow(clippy::too_many_arguments)]
async fn finalize(
    db: &sea_orm::DatabaseConnection,
    storage: &PgStorage,
    run_id: Uuid,
    fence: u64,
    c: &connections::Model,
    k: &dyn Connector,
    cr: &Credentials,
    checks: fn() -> Vec<Box<dyn Check>>,
) -> LResult<ChunkOutcome> {
    let partial = storage.load_run(run_id).await?.checkpoint.stats["partial"] == json!(true);
    let now = Utc::now();
    let cost = k.cost_daily(cr, 30).await.unwrap_or_else(|e| {
        // Cost visibility is optional (PRD 7.3): cost checks see no rows.
        tracing::warn!(error = %e, run = %run_id, "full_scan: cost unavailable");
        vec![]
    });
    let txn = db.begin().await.map_err(db_err)?;
    hold_fence(&txn, run_id, fence).await?;
    if !partial {
        exec(
            &txn,
            "UPDATE resources r SET gone_at = $3, updated_at = now() \
             WHERE r.connection_id = $1 AND r.gone_at IS NULL AND NOT EXISTS \
             (SELECT 1 FROM resource_history h WHERE h.resource_id = r.id AND h.run_id = $2)",
            vec![c.id.into(), run_id.into(), now.into()],
        )
        .await?;
    }
    let resources = seen(&txn, c, k, run_id).await?;
    let (provider, caps) = (k.provider(), k.capabilities());
    // Checks read utilisation from inventory attributes today; no metric pulls yet.
    let metrics = MetricStore::default();
    let cx = CheckCtx {
        connection_id: c.id,
        resources: &resources,
        cost: &cost,
        metrics: &metrics,
        now,
    };
    let (mut drafts, mut check_errors) = (vec![], vec![]);
    for ch in checks() {
        if !ch.supported().contains(&provider) || !ch.required().iter().all(|r| caps.contains(r)) {
            continue;
        }
        // A buggy check fails alone (PRD 7.3); the scan continues with the others.
        match catch_unwind(AssertUnwindSafe(|| ch.run(&cx))) {
            Ok(d) => drafts.extend(d),
            Err(_) => {
                tracing::error!(check_id = ch.id(), run = %run_id, "full_scan: check panicked");
                check_errors.push(ch.id());
            }
        }
    }
    finding_lifecycle::apply(&txn, c.id, run_id, &drafts, now, partial).await?;
    let mut stats = finding_lifecycle::posture(&txn, c.id).await?;
    stats["partial"] = json!(partial);
    stats["check_errors"] = json!(check_errors);
    txn.commit().await.map_err(db_err)?;
    Ok(ChunkOutcome { stats })
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
             WHERE r.connection_id = $1 ORDER BY r.identity",
            vec![c.id.into(), run_id.into()],
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
                kind: serde_json::from_value(json!(kind)).map_err(db_err)?,
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
