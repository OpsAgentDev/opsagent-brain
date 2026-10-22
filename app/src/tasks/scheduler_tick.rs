//! `scheduler:tick`: enqueue due schedules and due retries, then advance `next_due_at`.
//! The scheduler holds no state; the unique run key makes a repeated tick a no-op (jobs.md).
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use loco_rs::{
    app::AppContext,
    bgworker::BackgroundWorker,
    task::{Task, TaskInfo, Vars},
    Result,
};
use opsagent_core::run::RunKey;
use opsagent_ledger::{CreateRunOutcome, Storage};
use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DatabaseTransaction,
    TransactionTrait,
};
use uuid::Uuid;

use crate::{
    models::{
        ledger_storage::{stmt, PgStorage},
        schedules::next_after,
    },
    workers::{
        full_scan::{FullScanArgs, FullScanWorker},
        verify::{err, VerifyArgs, VerifyWorker},
    },
};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Runs handed to a real worker (no-op job types and duplicates are not counted).
    pub schedules_run: usize,
    pub retries_run: usize,
}

pub struct SchedulerTick;

#[async_trait]
impl Task for SchedulerTick {
    fn task(&self) -> TaskInfo {
        TaskInfo {
            name: "scheduler:tick".into(),
            detail: "Enqueue due schedules and retries (run every minute)".into(),
        }
    }

    async fn run(&self, ctx: &AppContext, _vars: &Vars) -> Result<()> {
        match tick(ctx, Utc::now()).await? {
            Some(r) => tracing::info!(?r, "scheduler tick"),
            None => tracing::info!("scheduler lock held elsewhere, skipping tick"),
        }
        Ok(())
    }
}

/// Enqueue the worker for a run; `false` for job types without a worker yet.
async fn enqueue(ctx: &AppContext, job_type: &str, run_id: Uuid) -> Result<bool> {
    match job_type {
        "verify" => VerifyWorker::perform_later(ctx, VerifyArgs { run_id }).await?,
        "full_scan" => FullScanWorker::perform_later(ctx, FullScanArgs { run_id }).await?,
        other => {
            tracing::warn!(job_type = other, %run_id, "no worker registered, not enqueued");
            return Ok(false);
        }
    };
    Ok(true)
}

/// Enqueue after the run row is committed (a worker must be able to load it), then clear the
/// outbox marker `due_schedule` set. Only the exact marker is cleared, so a retry time the
/// worker has since written survives. A crash in between leaves the marker for the next tick.
async fn dispatch(ctx: &AppContext, id: Uuid, job: &str, marker: DateTime<Utc>) -> Result<bool> {
    let sent = enqueue(ctx, job, id).await?;
    PgStorage::new(ctx.db.clone())
        .clear_enqueue_marker(id, marker)
        .await
        .map_err(err)?;
    Ok(sent)
}

/// One tick at `now`. `None` when another scheduler holds the advisory lock.
pub async fn tick(ctx: &AppContext, now: DateTime<Utc>) -> Result<Option<Report>> {
    // Dedicated pool, apart from `ctx.db` (size 1 in dev/test, and used by inline workers):
    // one connection holds the lock transaction, the other does the per-schedule work.
    let mut opts = ConnectOptions::new(ctx.config.database.uri.clone());
    opts.max_connections(2).min_connections(1);
    let db = Database::connect(opts).await?;
    // The transaction-level lock is released by commit/rollback/disconnect, never by us.
    let lock = db.begin().await?;
    let locked = lock
        .query_one_raw(stmt(
            "SELECT pg_try_advisory_xact_lock(hashtext('opsagent-scheduler')) AS ok",
            vec![],
        ))
        .await?
        .map(|r| r.try_get::<bool>("", "ok"))
        .transpose()?
        .unwrap_or(false);
    if !locked {
        return Ok(None);
    }
    let report = tick_locked(ctx, &db, now).await;
    lock.commit().await?;
    report.map(Some)
}

struct Due {
    key: RunKey,
    cron: String,
    tz: String,
}

/// Locks the schedule row if it is still due and unclaimed.
async fn lock_and_load(
    txn: &DatabaseTransaction,
    id: Uuid,
    now: DateTime<Utc>,
) -> Result<Option<Due>> {
    let Some(s) = txn
        .query_one_raw(stmt(
            "SELECT organisation_id, connection_id, job_type, cron_local, timezone, next_due_at \
             FROM schedules WHERE id = $1 AND enabled AND next_due_at <= $2 FOR UPDATE SKIP LOCKED",
            vec![id.into(), now.into()],
        ))
        .await?
    else {
        return Ok(None);
    };
    Ok(Some(Due {
        key: RunKey {
            organisation_id: s.try_get("", "organisation_id")?,
            connection_id: s.try_get("", "connection_id")?,
            job_type: s.try_get("", "job_type")?,
            scheduled_at: s.try_get("", "next_due_at")?,
        },
        cron: s.try_get("", "cron_local")?,
        tz: s.try_get("", "timezone")?,
    }))
}

/// Creates the run on the same transaction; a new run gets the outbox marker. Returns the
/// transaction back (the storage owns it while it works).
async fn create_and_mark(
    txn: DatabaseTransaction,
    key: RunKey,
    now: DateTime<Utc>,
) -> Result<(DatabaseTransaction, CreateRunOutcome)> {
    let storage = PgStorage::new(txn);
    let out = storage.create_run(key).await.map_err(err)?;
    if out.created {
        storage
            .mark_enqueue_pending(out.run.id, now)
            .await
            .map_err(err)?;
    }
    Ok((storage.into_inner(), out))
}

/// Moves `next_due_at` forward; `None` (unparseable cron or zone) disables the schedule.
async fn advance(txn: &DatabaseTransaction, id: Uuid, next: Option<DateTime<Utc>>) -> Result<()> {
    let st = match next {
        Some(t) => stmt(
            "UPDATE schedules SET next_due_at = $2, updated_at = now() WHERE id = $1",
            vec![id.into(), t.into()],
        ),
        None => stmt(
            "UPDATE schedules SET enabled = false, updated_at = now() WHERE id = $1",
            vec![id.into()],
        ),
    };
    txn.execute_raw(st).await?;
    Ok(())
}

/// One schedule, one transaction: lock, create the run, advance `next_due_at`, commit. Returns
/// the run only when this call created it.
async fn due_schedule(
    db: &DatabaseConnection,
    id: Uuid,
    now: DateTime<Utc>,
) -> Result<Option<(Uuid, String)>> {
    let txn = db.begin().await?;
    let Some(due) = lock_and_load(&txn, id, now).await? else {
        return Ok(None);
    };
    // Missed ticks collapse into this one run; the next slot is after `now` (PRD 7.3).
    let next = next_after(&due.cron, &due.tz, now);
    if next.is_none() {
        tracing::error!(schedule = %id, cron = due.cron, tz = due.tz, "invalid schedule, disabling");
        advance(&txn, id, None).await?;
        txn.commit().await?;
        return Ok(None);
    }
    let job = due.key.job_type.clone();
    let (txn, out) = create_and_mark(txn, due.key, now).await?;
    advance(&txn, id, next).await?;
    txn.commit().await?;
    Ok(out.created.then_some((out.run.id, job)))
}

async fn tick_locked(
    ctx: &AppContext,
    db: &DatabaseConnection,
    now: DateTime<Utc>,
) -> Result<Report> {
    let mut report = Report::default();
    let due = db
        .query_all_raw(stmt(
            "SELECT id FROM schedules WHERE enabled AND next_due_at <= $1 ORDER BY next_due_at",
            vec![now.into()],
        ))
        .await?;
    for id in due {
        let id: Uuid = id.try_get("", "id")?;
        // One bad schedule must not block the others; its transaction rolled back, so it is due again next tick.
        match due_schedule(db, id, now).await {
            Ok(Some((run, job))) => match dispatch(ctx, run, &job, now).await {
                Ok(sent) => report.schedules_run += usize::from(sent),
                Err(e) => {
                    tracing::error!(schedule = %id, %run, error = %e, "enqueue failed, the retry pass picks it up next tick")
                }
            },
            Ok(None) => {}
            Err(e) => tracing::error!(schedule = %id, error = %e, "schedule failed"),
        }
    }

    // Runs parked with `schedule_retry` (status queued + next_attempt_at), and runs whose
    // enqueue was interrupted after `due_schedule` committed them.
    let retries = db
        .query_all_raw(stmt(
            "SELECT id, job_type, next_attempt_at FROM runs WHERE status = 'queued' AND next_attempt_at IS NOT NULL \
             AND next_attempt_at <= $1 ORDER BY next_attempt_at",
            vec![now.into()],
        ))
        .await?;
    for r in retries {
        let id: Uuid = r.try_get("", "id")?;
        let (job, marker) = (
            r.try_get::<String>("", "job_type")?,
            r.try_get("", "next_attempt_at")?,
        );
        match dispatch(ctx, id, &job, marker).await {
            Ok(sent) => report.retries_run += usize::from(sent),
            Err(e) => tracing::error!(run = %id, error = %e, "retry enqueue failed"),
        }
    }
    Ok(report)
}
