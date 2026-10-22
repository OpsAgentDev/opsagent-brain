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
use opsagent_core::run::{RunKey, RunStatus};
use opsagent_ledger::Storage;
use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement,
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

/// Enqueue the worker for a run. Job types without a worker yet are logged and skipped.
async fn enqueue(ctx: &AppContext, job_type: &str, run_id: Uuid) -> Result<()> {
    match job_type {
        "verify" => VerifyWorker::perform_later(ctx, VerifyArgs { run_id }).await?,
        "full_scan" => FullScanWorker::perform_later(ctx, FullScanArgs { run_id }).await?,
        other => {
            tracing::warn!(job_type = other, %run_id, "no worker registered, not enqueued");
            return Ok(());
        }
    };
    Ok(())
}

/// One tick at `now`. `None` when another scheduler holds the advisory lock.
pub async fn tick(ctx: &AppContext, now: DateTime<Utc>) -> Result<Option<Report>> {
    // Dedicated single connection: the session advisory lock lives and dies with it, and the
    // pool (which may be size 1) stays free for the run storage and workers.
    let mut opts = ConnectOptions::new(ctx.config.database.uri.clone());
    opts.max_connections(1).min_connections(1);
    let conn = Database::connect(opts).await?;
    let locked = conn
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT pg_try_advisory_lock(hashtext('opsagent-scheduler')) AS ok",
        ))
        .await?
        .map(|r| r.try_get::<bool>("", "ok"))
        .transpose()?
        .unwrap_or(false);
    if !locked {
        return Ok(None);
    }
    let report = tick_locked(ctx, &conn, now).await;
    // Closing the connection would release it too; explicit unlock keeps that independent of drop order.
    let _ = conn
        .execute_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT pg_advisory_unlock(hashtext('opsagent-scheduler'))",
        ))
        .await;
    report.map(Some)
}

async fn tick_locked(
    ctx: &AppContext,
    conn: &DatabaseConnection,
    now: DateTime<Utc>,
) -> Result<Report> {
    let storage = PgStorage::new(ctx.db.clone());
    let txn = conn.begin().await?;
    let mut report = Report::default();

    let due = txn
        .query_all_raw(stmt(
            "SELECT id, organisation_id, connection_id, job_type, cron_local, timezone, next_due_at \
             FROM schedules WHERE enabled AND next_due_at <= $1 FOR UPDATE SKIP LOCKED",
            vec![now.into()],
        ))
        .await?;
    for s in due {
        let id: Uuid = s.try_get("", "id")?;
        let job_type: String = s.try_get("", "job_type")?;
        let due_at: DateTime<Utc> = s.try_get("", "next_due_at")?;
        let cron: String = s.try_get("", "cron_local")?;
        let tz: String = s.try_get("", "timezone")?;
        // Missed ticks collapse into this one run; the next slot is after `now` (PRD 7.3).
        let Some(next) = next_after(&cron, &tz, now) else {
            tracing::error!(schedule = %id, cron, tz, "invalid schedule, disabling");
            txn.execute_raw(stmt(
                "UPDATE schedules SET enabled = false, updated_at = now() WHERE id = $1",
                vec![id.into()],
            ))
            .await?;
            continue;
        };
        let run = storage
            .create_run(RunKey {
                organisation_id: s.try_get("", "organisation_id")?,
                connection_id: s.try_get("", "connection_id")?,
                job_type: job_type.clone(),
                scheduled_at: due_at,
            })
            .await
            .map_err(err)?;
        if run.status == RunStatus::Queued {
            enqueue(ctx, &job_type, run.id).await?;
            report.schedules_run += 1;
        }
        txn.execute_raw(stmt(
            "UPDATE schedules SET next_due_at = $2, updated_at = now() WHERE id = $1",
            vec![id.into(), next.into()],
        ))
        .await?;
    }

    // Retries the ledger parked with `schedule_retry` (status queued + next_attempt_at).
    let retries = txn
        .query_all_raw(stmt(
            "SELECT id, job_type FROM runs WHERE status = 'queued' AND next_attempt_at IS NOT NULL \
             AND next_attempt_at <= $1 FOR UPDATE SKIP LOCKED",
            vec![now.into()],
        ))
        .await?;
    for r in retries {
        let id: Uuid = r.try_get("", "id")?;
        enqueue(ctx, &r.try_get::<String>("", "job_type")?, id).await?;
        txn.execute_raw(stmt(
            "UPDATE runs SET next_attempt_at = NULL, updated_at = now() WHERE id = $1",
            vec![id.into()],
        ))
        .await?;
        report.retries_run += 1;
    }
    txn.commit().await?;
    Ok(report)
}
