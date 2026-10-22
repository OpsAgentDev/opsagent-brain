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
use opsagent_ledger::{
    lease, retry::settle, run_chunked, ChunkOutcome, LedgerError, RunChunkedOptions, RunRow,
    Storage,
};
use sea_orm::{ConnectionTrait, DatabaseConnection, EntityTrait, TransactionTrait};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use super::common::{err, job_err, lerr, redis_client, revoked, LResult};
use crate::{
    app::{kek, registry},
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
        let opts = RunChunkedOptions {
            worker_id: format!("{JOB}-{}", Uuid::new_v4()),
            time_cap: TIME_CAP,
            ..Default::default()
        };
        match run(&self.ctx, args.run_id, opts).await {
            // Another worker holds or took over the run; it decides the outcome.
            Ok(_) | Err(LedgerError::LeaseHeld | LedgerError::StaleFence) => Ok(()),
            Err(e) => Err(err(e)),
        }
    }
}

fn service(r: &Resource) -> &str {
    r.attributes["service"].as_str().unwrap_or("")
}

/// Runs (or resumes) the scan for `run_id` with the registry's connector. The run row must exist.
pub async fn run(ctx: &AppContext, run_id: Uuid, opts: RunChunkedOptions) -> LResult<RunStatus> {
    scan_run(ctx, run_id, None, opts, opsagent_checks::all).await
}

/// `run` with connector `k`.
pub async fn scan(
    ctx: &AppContext,
    run_id: Uuid,
    k: &dyn Connector,
    opts: RunChunkedOptions,
) -> LResult<RunStatus> {
    scan_run(ctx, run_id, Some(k), opts, opsagent_checks::all).await
}

/// `scan` with an explicit check set (tests inject faulty checks).
pub async fn scan_with(
    ctx: &AppContext,
    run_id: Uuid,
    k: &dyn Connector,
    opts: RunChunkedOptions,
    checks: fn() -> Vec<Box<dyn Check>>,
) -> LResult<RunStatus> {
    scan_run(ctx, run_id, Some(k), opts, checks).await
}

/// How a run ends without (more) chunks.
enum End {
    Set(RunStatus, String),
    /// Retried or failed by `ledger::retry::settle`.
    Failed(LedgerError),
}

async fn scan_run(
    ctx: &AppContext,
    run_id: Uuid,
    k: Option<&dyn Connector>,
    opts: RunChunkedOptions,
    checks: fn() -> Vec<Box<dyn Check>>,
) -> LResult<RunStatus> {
    let storage = PgStorage::new(ctx.db.clone());
    let run = storage.load_run(run_id).await?;
    if !matches!(run.status, RunStatus::Queued | RunStatus::Running) {
        return Ok(run.status); // duplicate delivery of a finished run
    }
    let c = connection(&ctx.db, &run).await?;
    if !matches!(status_of(&c).map_err(lerr)?, S::Connected | S::Degraded) {
        let skip = End::Set(RunStatus::Skipped, format!("status:{}", c.status));
        return end(ctx, &storage, &run, &opts, skip).await;
    }
    let owned;
    let k = match (k, connector(ctx, &c)) {
        (Some(k), _) => k,
        (None, Ok(b)) => {
            owned = b;
            owned.as_ref()
        }
        (None, Err(e)) => return end(ctx, &storage, &run, &opts, End::Failed(e)).await,
    };
    let cr = match call_credentials(ctx, &c, run_id).await {
        Ok(cr) => cr,
        Err(e) => return end(ctx, &storage, &run, &opts, End::Failed(e)).await,
    };
    let chunks = match discover(k, &cr).await {
        Ok(chunks) => chunks,
        Err(e) => return end(ctx, &storage, &run, &opts, e).await,
    };
    let redis = redis_client(ctx).map_err(lerr)?;
    let scan = Scan {
        db: &ctx.db,
        storage: &storage,
        run_id,
        c: &c,
        k,
        cr: &cr,
        checks,
    };
    run_chunked(&storage, &redis, run_id, chunks, opts, |chunk, lease| {
        scan.chunk(chunk, lease.fence)
    })
    .await
}

async fn connection(db: &DatabaseConnection, run: &RunRow) -> LResult<connections::Model> {
    let conn_id = run.key.connection_id.ok_or(LedgerError::NotFound)?;
    connections::Entity::find_by_id(conn_id)
        .one(db)
        .await
        .map_err(lerr)?
        .ok_or(LedgerError::NotFound)
}

fn connector(ctx: &AppContext, c: &connections::Model) -> LResult<Box<dyn Connector>> {
    registry(ctx)
        .map_err(lerr)?
        .connector(&c.provider)
        .map_err(|e| job_err(&e))
}

/// Decrypted call credentials; failures are not retryable.
async fn call_credentials(
    ctx: &AppContext,
    c: &connections::Model,
    run_id: Uuid,
) -> LResult<Credentials> {
    let kek = kek(ctx).map_err(lerr)?;
    let creds = load_creds(&ctx.db, kek.as_ref(), c)
        .await
        .map_err(|_| LedgerError::Job {
            code: "credentials_unavailable".into(),
            retry: false,
        })?;
    let context = CallContext {
        organisation_id: c.organisation_id,
        run_id,
        trigger: JOB.into(),
    };
    providers::credentials(&c.provider, &creds, context).map_err(|e| job_err(&e))
}

/// The chunk list (`service@region`, then `finalize`) from an unscoped inventory call.
/// shortcut: re-run on every (re)start, which doubles the AWS calls; upgrade to a declared
/// connector scope when the AWS connector exposes one.
async fn discover(k: &dyn Connector, cr: &Credentials) -> std::result::Result<Vec<String>, End> {
    let inv = k.inventory(cr, &Scope::default()).await.map_err(|e| {
        if revoked(&e) {
            End::Set(RunStatus::Partial, "revoked".into())
        } else {
            End::Failed(job_err(&e))
        }
    })?;
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
    Ok(chunks)
}

/// Sets the final status (or retries) under a lease of its own.
async fn end(
    ctx: &AppContext,
    storage: &PgStorage,
    run: &RunRow,
    opts: &RunChunkedOptions,
    how: End,
) -> LResult<RunStatus> {
    let redis = redis_client(ctx).map_err(lerr)?;
    let l = lease::acquire(storage, &redis, run.id, &opts.worker_id, opts.lease_ttl)
        .await?
        .ok_or(LedgerError::LeaseHeld)?;
    let res = match how {
        End::Set(status, reason) => storage
            .set_status(run.id, l.fence, status, Some(reason))
            .await
            .map(|()| status),
        End::Failed(e) => settle(storage, run.id, run.attempts, l.fence, &e).await,
    };
    lease::release(&redis, &l).await;
    res
}

/// One scan run's fixed inputs, shared by its chunks.
struct Scan<'a> {
    db: &'a DatabaseConnection,
    storage: &'a PgStorage,
    run_id: Uuid,
    c: &'a connections::Model,
    k: &'a dyn Connector,
    cr: &'a Credentials,
    checks: fn() -> Vec<Box<dyn Check>>,
}

impl Scan<'_> {
    async fn chunk(&self, chunk: String, fence: u64) -> LResult<ChunkOutcome> {
        if chunk == FINALIZE {
            return self.finalize(fence).await;
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
        let stats = match &inv {
            Err(e) if revoked(e) => json!({ "partial": true, "revoked": true }),
            _ if partial => json!({ "partial": true, "partial_reason": "partial_inventory" }),
            _ => json!({}),
        };
        Ok(ChunkOutcome { stats })
    }

    /// Gone-marking, checks, lifecycle and posture, in one fenced transaction.
    async fn finalize(&self, fence: u64) -> LResult<ChunkOutcome> {
        let (db, run_id, c, k) = (self.db, self.run_id, self.c, self.k);
        let so_far = self.storage.load_run(run_id).await?.checkpoint.stats;
        let partial = so_far["partial"] == json!(true);
        let now = Utc::now();
        let cost = k.cost_daily(self.cr, 30).await.unwrap_or_else(|e| {
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
        let (drafts, check_errors) = run_checks(self.checks, k, c, &resources, &cost, now, run_id);
        finding_lifecycle::apply(&txn, c.id, run_id, &drafts, now, partial).await?;
        let mut stats = finding_lifecycle::posture(&txn, c.id).await?;
        stats["partial"] = json!(partial);
        stats["check_errors"] = json!(check_errors);
        if so_far["revoked"] == json!(true) {
            stats["partial_reason"] = json!("revoked");
        }
        txn.commit().await.map_err(db_err)?;
        Ok(ChunkOutcome { stats })
    }
}

/// Runs every check that supports the provider and has its capabilities. A buggy check fails
/// alone (PRD 7.3); its id is returned in the second list.
fn run_checks(
    checks: fn() -> Vec<Box<dyn Check>>,
    k: &dyn Connector,
    c: &connections::Model,
    resources: &[Resource],
    cost: &[opsagent_connectors::CostRow],
    now: chrono::DateTime<Utc>,
    run_id: Uuid,
) -> (Vec<opsagent_core::finding::FindingDraft>, Vec<&'static str>) {
    let (provider, caps) = (k.provider(), k.capabilities());
    // Checks read utilisation from inventory attributes today; no metric pulls yet.
    let metrics = MetricStore::default();
    let cx = CheckCtx {
        connection_id: c.id,
        resources,
        cost,
        metrics: &metrics,
        now,
    };
    let (mut drafts, mut check_errors) = (vec![], vec![]);
    for ch in checks() {
        if !ch.supported().contains(&provider) || !ch.required().iter().all(|r| caps.contains(r)) {
            continue;
        }
        match catch_unwind(AssertUnwindSafe(|| ch.run(&cx))) {
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
