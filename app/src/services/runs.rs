//! Creating runs and handing them to workers (jobs.md). A new run carries the outbox marker
//! (`next_attempt_at`) until its enqueue is confirmed, so an enqueue lost to a crash or a
//! queue error is picked up again by the scheduler's retry pass.
use chrono::{DateTime, Utc};
use loco_rs::{app::AppContext, bgworker::BackgroundWorker, Result};
use opsagent_core::run::RunKey;
use opsagent_ledger::{CreateRunOutcome, Storage};
use sea_orm::ConnectionTrait;
use uuid::Uuid;

use crate::{
    models::ledger_storage::PgStorage,
    workers::{
        common::err,
        deliver_briefing::{DeliverBriefingArgs, DeliverBriefingWorker},
        deliver_weekly::{DeliverWeeklyArgs, DeliverWeeklyWorker},
        full_scan::{FullScanArgs, FullScanWorker},
        verify::{VerifyArgs, VerifyWorker},
    },
};

/// Hands `run_id` to the worker for `job_type`; `false` for job types without a worker yet.
async fn send(ctx: &AppContext, job_type: &str, run_id: Uuid) -> Result<bool> {
    match job_type {
        "verify" => VerifyWorker::perform_later(ctx, VerifyArgs { run_id }).await?,
        "full_scan" => FullScanWorker::perform_later(ctx, FullScanArgs { run_id }).await?,
        "deliver_briefing" => {
            DeliverBriefingWorker::perform_later(ctx, DeliverBriefingArgs { run_id }).await?
        }
        "deliver_weekly" => {
            DeliverWeeklyWorker::perform_later(ctx, DeliverWeeklyArgs { run_id }).await?
        }
        other => {
            tracing::warn!(job_type = other, %run_id, "no worker registered, not enqueued");
            return Ok(false);
        }
    };
    Ok(true)
}

/// Creates the run on `db` (pass a transaction to commit it with other writes); a new run
/// gets the outbox marker `now`. Returns `db` back.
pub async fn create_marked<C: ConnectionTrait + Send + Sync>(
    db: C,
    key: RunKey,
    now: DateTime<Utc>,
) -> Result<(C, CreateRunOutcome)> {
    let storage = PgStorage::new(db);
    let out = mark_new(&storage, key, now).await?;
    Ok((storage.into_inner(), out))
}

/// `create_marked` through a storage the caller already holds (e.g. on its transaction).
pub async fn mark_new<S: Storage + ?Sized>(
    storage: &S,
    key: RunKey,
    now: DateTime<Utc>,
) -> Result<CreateRunOutcome> {
    let out = storage.create_run(key).await.map_err(err)?;
    if out.created {
        storage
            .mark_enqueue_pending(out.run.id, now)
            .await
            .map_err(err)?;
    }
    Ok(out)
}

/// Once the run is committed (a worker must be able to load it): enqueue, then clear the
/// marker. Only the exact `marker` is cleared, so a retry time a worker has since written
/// survives; a crash in between leaves the marker for the next tick.
pub async fn dispatch(
    ctx: &AppContext,
    run_id: Uuid,
    job_type: &str,
    marker: DateTime<Utc>,
) -> Result<bool> {
    let sent = send(ctx, job_type, run_id).await?;
    PgStorage::new(ctx.db.clone())
        .clear_enqueue_marker(run_id, marker)
        .await
        .map_err(err)?;
    Ok(sent)
}

/// `create_marked` on the pool, then `dispatch` if the run is new (a duplicate key is the
/// run already handed off). A failed hand-off is logged, not returned: the run is recorded
/// and the retry pass sends it.
pub async fn enqueue(
    ctx: &AppContext,
    key: RunKey,
    now: DateTime<Utc>,
) -> Result<CreateRunOutcome> {
    let job = key.job_type.clone();
    let (_, out) = create_marked(ctx.db.clone(), key, now).await?;
    if out.created {
        hand_off(ctx, &out, &job, now).await;
    }
    Ok(out)
}

/// `dispatch`, logging a failure (the marker stays, so the retry pass sends the run).
pub async fn hand_off(
    ctx: &AppContext,
    out: &CreateRunOutcome,
    job_type: &str,
    marker: DateTime<Utc>,
) {
    if let Err(e) = dispatch(ctx, out.run.id, job_type, marker).await {
        tracing::error!(run = %out.run.id, job_type, error = %e, "enqueue failed, the retry pass picks it up");
    }
}
