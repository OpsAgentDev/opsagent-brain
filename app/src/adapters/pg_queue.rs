//! Postgres job queue (app-shell.md, "Jobs table"): enqueue in the caller's transaction, drain
//! with `FOR UPDATE SKIP LOCKED`. The `jobs` table is global; a job names its run.
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::run::RunStatus;
use opsagent_ledger::{
    queue::{Job, JobFailure, JobSource},
    retry, JobKind, NewJob, Queue, Result, Storage,
};
use sea_orm::{ConnectionTrait, DatabaseConnection, QueryResult, TransactionTrait};
use uuid::Uuid;

use super::db::{
    ledger_storage::{db_err, stmt},
    Conn, Pg,
};

const MAX_ATTEMPTS: i32 = 5;

/// `C` is a pool or a borrowed transaction for enqueueing; the pool also drains.
pub struct PgQueue<C>(pub C);

#[async_trait]
impl<C: Conn> Queue for PgQueue<C> {
    async fn enqueue(&self, job: NewJob) -> Result<()> {
        let args = serde_json::json!({ "run_id": job.run_id });
        self.0
            .conn()
            .execute_raw(stmt(
                // tenancy: job queue is global
                "INSERT INTO jobs (kind, args, run_id, run_at, max_attempts) \
                 VALUES ($1, $2, $3, $4, $5) \
                 ON CONFLICT (run_id) WHERE run_id IS NOT NULL DO NOTHING",
                vec![
                    job.kind.as_str().into(),
                    args.into(),
                    job.run_id.into(),
                    job.run_at.into(),
                    MAX_ATTEMPTS.into(),
                ],
            ))
            .await
            .map(drop)
            .map_err(db_err)
    }
}

/// A `Pg` transaction enqueues on itself, so the job commits with the run.
#[async_trait]
impl<C: Conn> Queue for Pg<C> {
    async fn enqueue(&self, job: NewJob) -> Result<()> {
        PgQueue(self.db()).enqueue(job).await
    }
}

fn job(r: &QueryResult) -> Result<Job> {
    let kind: String = r.try_get("", "kind").map_err(db_err)?;
    Ok(Job {
        id: r.try_get("", "id").map_err(db_err)?,
        kind: JobKind::parse(&kind).ok_or_else(|| db_err(format!("unknown job kind {kind:?}")))?,
        run_id: r.try_get("", "run_id").map_err(db_err)?,
        attempts: r.try_get("", "attempts").map_err(db_err)?,
        max_attempts: r.try_get("", "max_attempts").map_err(db_err)?,
    })
}

async fn exec(db: &impl ConnectionTrait, sql: &str, values: Vec<sea_orm::Value>) -> Result<u64> {
    db.execute_raw(stmt(sql, values))
        .await
        .map(|r| r.rows_affected())
        .map_err(db_err)
}

impl PgQueue<DatabaseConnection> {
    /// Marks one job dead with `mark` (an UPDATE returning `run_id` that leaves the row locked
    /// with no owner) and fails its run, in one transaction. The fence is bumped first, as
    /// `skip_run` does, so a worker still holding the lease cannot write a competing status.
    async fn bury(&self, mark: &str, values: Vec<sea_orm::Value>) -> Result<Option<Uuid>> {
        let txn = self.0.begin().await.map_err(db_err)?;
        let Some(r) = txn
            .query_one_raw(stmt(mark, values))
            .await
            .map_err(db_err)?
        else {
            return Ok(None);
        };
        let run_id: Uuid = r.try_get("", "run_id").map_err(db_err)?;
        let runs = Pg::new(&txn);
        let fence = runs.bump_fence(run_id).await?;
        let run = runs.load_run(run_id).await?;
        if matches!(run.status, RunStatus::Queued | RunStatus::Running) {
            runs.fail_run(run_id, fence, "job_attempts_exhausted")
                .await?;
        }
        txn.commit().await.map_err(db_err)?;
        Ok(Some(run_id))
    }
}

#[async_trait]
impl JobSource for PgQueue<DatabaseConnection> {
    async fn dequeue(
        &self,
        worker_id: &str,
        kinds: &[JobKind],
        lock_max_age: Duration,
    ) -> Result<Option<Job>> {
        // A stale lock on the last attempt is not handed out again: the job is dead.
        while self
            .bury(
                // tenancy: job queue is global
                "UPDATE jobs SET locked_by = NULL, last_error = 'lock_expired' \
                 WHERE id = (SELECT id FROM jobs WHERE locked_by IS NOT NULL \
                   AND locked_at < now() - make_interval(secs => $1) \
                   AND attempts >= max_attempts FOR UPDATE SKIP LOCKED LIMIT 1) \
                 RETURNING run_id",
                vec![lock_max_age.as_secs_f64().into()],
            )
            .await?
            .is_some()
        {}
        let kinds: Vec<String> = kinds.iter().map(|k| k.as_str().to_owned()).collect();
        // A stale lock is free unless the job is dead (attempts exhausted).
        let row = self
            .0
            .query_one_raw(stmt(
                // tenancy: job queue is global
                "UPDATE jobs SET locked_at = now(), locked_by = $1, attempts = attempts + 1 \
                 WHERE id = (SELECT id FROM jobs WHERE run_at <= now() AND kind = ANY($2) \
                   AND (locked_at IS NULL OR (locked_at < now() - make_interval(secs => $3) \
                        AND attempts < max_attempts)) \
                   ORDER BY run_at FOR UPDATE SKIP LOCKED LIMIT 1) \
                 RETURNING id, kind, run_id, attempts, max_attempts",
                vec![
                    worker_id.into(),
                    kinds.into(),
                    lock_max_age.as_secs_f64().into(),
                ],
            ))
            .await
            .map_err(db_err)?;
        row.as_ref().map(job).transpose()
    }

    async fn complete(&self, job: &Job) -> Result<bool> {
        // tenancy: job queue is global
        let sql = "DELETE FROM jobs WHERE id = $1 AND attempts = $2 AND locked_at IS NOT NULL";
        let n = exec(&self.0, sql, vec![job.id.into(), job.attempts.into()]).await?;
        Ok(n == 1)
    }

    async fn fail(&self, job: &Job, error: &str, now: DateTime<Utc>) -> Result<JobFailure> {
        // `attempts` includes this one; backoff counts the retries before it.
        let retries = u32::try_from(job.attempts - 1).unwrap_or(0);
        let wait = retry::backoff(retries).filter(|_| job.attempts < job.max_attempts);
        if let Some(wait) = wait {
            let at = now + chrono::Duration::from_std(wait).map_err(db_err)?;
            let n = exec(
                &self.0,
                // tenancy: job queue is global
                "UPDATE jobs SET locked_at = NULL, locked_by = NULL, run_at = $2, last_error = $3 \
                 WHERE id = $1 AND attempts = $4 AND locked_at IS NOT NULL",
                vec![job.id.into(), at.into(), error.into(), job.attempts.into()],
            )
            .await?;
            return Ok(if n == 1 {
                JobFailure::Retrying { at }
            } else {
                JobFailure::LockLost
            });
        }
        let dead = self
            .bury(
                // tenancy: job queue is global
                "UPDATE jobs SET last_error = $2, locked_by = NULL \
                 WHERE id = $1 AND attempts = $3 AND locked_at IS NOT NULL RETURNING run_id",
                vec![job.id.into(), error.into(), job.attempts.into()],
            )
            .await?;
        Ok(match dead {
            Some(_) => JobFailure::Dead,
            None => JobFailure::LockLost,
        })
    }

    async fn release_mine(&self, worker_id: &str) -> Result<u64> {
        exec(
            &self.0,
            // tenancy: job queue is global
            // Due after the dropped handlers' ledger leases (max 120 s) lapse: taken sooner, the
            // job would meet `LeaseHeld`, count as settled and be deleted with its run unfinished.
            "UPDATE jobs SET locked_at = NULL, locked_by = NULL, \
             attempts = GREATEST(attempts - 1, 0), run_at = now() + interval '150 seconds' \
             WHERE locked_by = $1",
            vec![worker_id.into()],
        )
        .await
    }
}
