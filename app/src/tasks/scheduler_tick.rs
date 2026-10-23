//! `scheduler:tick`: enqueue due schedules and due retries, then advance `next_due_at`.
//! The scheduler holds no state; the unique run key makes a repeated tick a no-op (jobs.md).
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use loco_rs::{
    app::AppContext,
    task::{Task, TaskInfo, Vars},
    Result,
};
use opsagent_core::run::RunKey;
use opsagent_ledger::Storage;
use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DatabaseTransaction,
    TransactionTrait,
};
use uuid::Uuid;

use crate::{
    models::{
        ledger_storage::{stmt, PgStorage},
        schedules::{backfill_defaults, next_after},
    },
    services::runs::{create_marked, dispatch},
    workers::common::err,
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
            "SELECT s.organisation_id, s.connection_id, s.job_type, s.cron_local, s.timezone, s.next_due_at \
             FROM schedules s WHERE s.id = $1 AND s.enabled AND s.next_due_at <= $2 \
             AND NOT EXISTS (SELECT 1 FROM organisations o WHERE o.id = s.organisation_id AND o.deleted_at IS NOT NULL) \
             FOR UPDATE OF s SKIP LOCKED",
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

/// Moves `next_due_at` forward; `None` (unparseable cron or zone) disables the schedule.
async fn advance(txn: &DatabaseTransaction, id: Uuid, next: Option<DateTime<Utc>>) -> Result<()> {
    // tenancy: the scheduler serves every organisation; the row was locked by id just before.
    let st = match next {
        Some(t) => stmt(
            "UPDATE schedules SET next_due_at = $2, updated_at = now() WHERE id = $1",
            vec![id.into(), t.into()],
        ),
        // tenancy: as above.
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
    let (txn, out) = create_marked(txn, due.key, now).await?;
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
    // Connections verified before delivery schedules existed get them here, before the due scan.
    if let Err(e) = backfill_defaults(db, now).await {
        tracing::error!(error = %e, "schedule backfill failed");
    }
    let due = db
        .query_all_raw(stmt(
            // Deleted organisations are never scheduled (their schedules are disabled on delete too).
            "SELECT s.id FROM schedules s WHERE s.enabled AND s.next_due_at <= $1 AND NOT EXISTS \
             (SELECT 1 FROM organisations o WHERE o.id = s.organisation_id AND o.deleted_at IS NOT NULL) \
             ORDER BY s.next_due_at",
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
    report.retries_run = retry_pass(ctx, db, now).await?;
    Ok(report)
}

/// Deleted organisations get no more work: their due parked runs end `Skipped` (fenced, so a
/// worker already holding a lease cannot revive one) instead of waiting forever.
async fn skip_deleted_orgs(db: &DatabaseConnection, now: DateTime<Utc>) -> Result<()> {
    let txn = PgStorage::new(db.begin().await?);
    let gone = txn
        .db()
        .query_all_raw(stmt(
            "SELECT r.id FROM runs r WHERE r.status = 'queued' AND r.next_attempt_at IS NOT NULL \
             AND r.next_attempt_at <= $1 AND EXISTS (SELECT 1 FROM organisations o \
             WHERE o.id = r.organisation_id AND o.deleted_at IS NOT NULL)",
            vec![now.into()],
        ))
        .await?;
    for r in gone {
        let id: Uuid = r.try_get("", "id")?;
        txn.skip_run(id, "org_deleted").await.map_err(err)?;
    }
    txn.into_inner().commit().await?;
    Ok(())
}

/// Runs parked with `schedule_retry` (status queued + next_attempt_at), and runs whose
/// enqueue was interrupted after they were committed (the outbox marker); those of deleted
/// organisations are skipped. Returns how many were handed to a worker.
async fn retry_pass(
    ctx: &AppContext,
    db: &DatabaseConnection,
    now: DateTime<Utc>,
) -> Result<usize> {
    skip_deleted_orgs(db, now).await?;
    let mut sent_total = 0;
    let retries = db
        .query_all_raw(stmt(
            "SELECT r.id, r.job_type, r.next_attempt_at FROM runs r WHERE r.status = 'queued' \
             AND r.next_attempt_at IS NOT NULL AND r.next_attempt_at <= $1 AND NOT EXISTS \
             (SELECT 1 FROM organisations o WHERE o.id = r.organisation_id AND o.deleted_at IS NOT NULL) \
             ORDER BY r.next_attempt_at",
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
            Ok(sent) => sent_total += usize::from(sent),
            Err(e) => tracing::error!(run = %id, error = %e, "retry enqueue failed"),
        }
    }
    Ok(sent_total)
}
