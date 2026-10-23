//! `full_scan` job (PRD 7.3, jobs.md): one chunk per service × region, then a `finalize` chunk
//! that marks unseen resources gone, runs the checks and applies the finding lifecycle.
mod chunks;
use std::{collections::BTreeSet, time::Duration};

use async_trait::async_trait;
use loco_rs::{app::AppContext, bgworker::BackgroundWorker, Result};
use opsagent_checks::Check;
use opsagent_connectors::{registry as providers, CallContext, Connector, Credentials, Scope};
use opsagent_core::audit::{AuditEntry, AuditLog};
use opsagent_core::{connection::ConnectionStatus as S, run::RunStatus};
use opsagent_ledger::{
    lease::{self, claim, unclaim},
    retry::{fail_on_storage_error, settle},
    run_chunked, LedgerError, RunChunkedOptions, RunRow, Storage,
};
use sea_orm::{ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use self::chunks::Scan;
use super::common::{err, job_err, lerr, redis_client, revoked, LResult};
use crate::{
    adapters::db::Pg,
    app::{kek, registry},
    models::{
        _entities::connections,
        connections::{load_creds, status_of},
        ledger_storage::{db_err, stmt, PgStorage},
    },
};
use opsagent_core::org::OrganisationsRepo;

pub const JOB: &str = "full_scan";
const SIMULATE: &str = "simulate";
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
    if Pg::new(&ctx.db)
        .is_deleted(c.organisation_id)
        .await
        .map_err(lerr)?
    {
        let skip = End::Set(RunStatus::Skipped, "organisation_deleted".into());
        return end(ctx, &storage, &run, &opts, skip).await;
    }
    if !matches!(status_of(&c).map_err(lerr)?, S::Connected | S::Degraded) {
        let skip = End::Set(RunStatus::Skipped, format!("status:{}", c.status));
        return end(ctx, &storage, &run, &opts, skip).await;
    }
    // At most one full scan per connection (PRD 7.3); the run id owns the claim, so a resumed
    // run passes and any other run is skipped.
    let redis = redis_client(ctx).map_err(lerr)?;
    let (key, owner) = (format!("lease:conn:{}:{JOB}", c.id), run_id.to_string());
    if !claim(&redis, &key, &owner, opts.time_cap + opts.lease_ttl).await? {
        let skip = End::Set(RunStatus::Skipped, "overlap".into());
        return end(ctx, &storage, &run, &opts, skip).await;
    }
    let res = claimed(ctx, &storage, &run, &c, k, opts, checks).await;
    // A worker that took over this run's lease is still scanning: leave the claim to it.
    if !matches!(
        storage.load_run(run_id).await.map(|r| r.status),
        Ok(RunStatus::Running)
    ) {
        unclaim(&redis, &key, &owner).await;
    }
    res
}

/// The scan proper, once the connection is claimed: credentials, discovery, chunks.
async fn claimed(
    ctx: &AppContext,
    storage: &PgStorage,
    run: &RunRow,
    c: &connections::Model,
    k: Option<&dyn Connector>,
    opts: RunChunkedOptions,
    checks: fn() -> Vec<Box<dyn Check>>,
) -> LResult<RunStatus> {
    let owned;
    let k = match k {
        Some(k) => k,
        None => match connector(ctx, c) {
            Ok(b) => {
                owned = b;
                owned.as_ref()
            }
            Err(e) => return end(ctx, storage, run, &opts, End::Failed(e)).await,
        },
    };
    let cr = match call_credentials(ctx, c, run.id).await {
        Ok(cr) => cr,
        Err(e) => return end(ctx, storage, run, &opts, End::Failed(e)).await,
    };
    if let Err(e) = audit_start(&ctx.db, c, run.id).await {
        return end(ctx, storage, run, &opts, End::Failed(e)).await;
    }
    let chunks = match discover(k, &cr).await {
        Ok(chunks) => chunks,
        Err(e) => return end(ctx, storage, run, &opts, e).await,
    };
    let redis = redis_client(ctx).map_err(lerr)?;
    let scan = Scan {
        db: &ctx.db,
        storage,
        run_id: run.id,
        c,
        k,
        cr: &cr,
        checks,
    };
    run_chunked(storage, &redis, run.id, chunks, opts, |chunk, lease| {
        scan.chunk(chunk, lease.fence)
    })
    .await
}

/// `connection.scan_started`, once per run: a resumed or retried run does not repeat it.
async fn audit_start(db: &DatabaseConnection, c: &connections::Model, run_id: Uuid) -> LResult<()> {
    let seen = db
        .query_one_raw(stmt(
            "SELECT 1 FROM audit_events WHERE organisation_id = $1 \
             AND action = 'connection.scan_started' AND metadata->>'run_id' = $2",
            vec![c.organisation_id.into(), run_id.to_string().into()],
        ))
        .await
        .map_err(db_err)?
        .is_some();
    if seen {
        return Ok(());
    }
    let target = ("connection", c.id.to_string());
    let meta = json!({ "run_id": run_id });
    Pg::new(db)
        .record(
            AuditEntry::system(
                c.organisation_id,
                "connection.scan_started",
                target,
                "success",
            )
            .with_meta(meta),
        )
        .await
        .map_err(db_err)
}

async fn connection(db: &DatabaseConnection, run: &RunRow) -> LResult<connections::Model> {
    let conn_id = run.key.connection_id.ok_or(LedgerError::NotFound)?;
    connections::Entity::find_by_id(conn_id)
        .filter(connections::Column::OrganisationId.eq(run.key.organisation_id))
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

/// The chunk list (`service@region`, then `simulate` and `finalize`) from an unscoped inventory call.
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
        .map(|r| (r.service(), r.region.as_str()))
        .chain(
            inv.partial_errors
                .iter()
                .map(|e| (e.service.as_str(), e.region.as_str())),
        )
        .map(|(s, r)| format!("{s}@{r}"))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    chunks.extend([SIMULATE.into(), FINALIZE.into()]);
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
    let res = fail_on_storage_error(storage, run.id, l.fence, res).await;
    lease::release(&redis, &l).await;
    res
}
