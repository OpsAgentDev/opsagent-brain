//! `SchedulerTick`: enqueue due schedules and due retries, then advance `next_due_at`.
//! The scheduler holds no state; the unique run key makes a repeated tick a no-op (jobs.md).
use std::sync::Arc;

use chrono::{DateTime, Utc};
use opsagent_deliver::{repo::SchedulesRepo, schedule::next_after};
use opsagent_ledger::Storage;
use sea_orm::{ConnectOptions, Database, DatabaseConnection, TransactionTrait};
use uuid::Uuid;

use super::RunDispatcher;
use crate::{
    adapters::db::{db_err, Pg},
    error::AppResult,
};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct TickReport {
    /// Runs handed to a real worker (no-op job types and duplicates are not counted).
    pub schedules_run: usize,
    pub retries_run: usize,
}

pub struct SchedulerTick {
    db_url: String,
    dispatcher: Arc<RunDispatcher>,
}

impl SchedulerTick {
    pub fn new(db_url: String, dispatcher: Arc<RunDispatcher>) -> Self {
        Self { db_url, dispatcher }
    }

    /// One tick at `now`. `None` when another scheduler holds the advisory lock.
    pub async fn run(&self, now: DateTime<Utc>) -> AppResult<Option<TickReport>> {
        // shortcut: the tick builds its own Pg adapter (a dedicated pool) rather than taking a
        // UnitOfWork, because the lock needs one connection held for the whole tick; revisit
        // when the shell owns the pools (Task 13).
        // Dedicated pool, apart from the app pool (size 1 in dev/test, and used by inline
        // workers): one connection holds the lock transaction, the other does the per-schedule work.
        let mut opts = ConnectOptions::new(self.db_url.clone());
        opts.max_connections(2).min_connections(1);
        let db = Database::connect(opts).await.map_err(db_err)?;
        // The transaction-level lock is released by commit/rollback/disconnect, never by us.
        let lock = Pg::new(db.begin().await.map_err(db_err)?);
        if !lock.try_lock_scheduler().await? {
            return Ok(None);
        }
        let report = self.locked(&db, now).await;
        lock.into_inner().commit().await.map_err(db_err)?;
        report.map(Some)
    }

    /// One schedule, one transaction: lock, create the run, advance `next_due_at`, commit.
    /// Returns the run only when this call created it.
    async fn due_schedule(
        &self,
        db: &DatabaseConnection,
        id: Uuid,
        now: DateTime<Utc>,
    ) -> AppResult<Option<(Uuid, String)>> {
        let txn = Pg::new(db.begin().await.map_err(db_err)?);
        let Some((key, cron, tz)) = txn.lock_due(id, now).await? else {
            return Ok(None);
        };
        // Missed ticks collapse into this one run; the next slot is after `now` (PRD 7.3).
        let next = next_after(&cron, &tz, now);
        if next.is_none() {
            tracing::error!(schedule = %id, cron, tz, "invalid schedule, disabling");
            txn.advance(id, None).await?;
            txn.into_inner().commit().await.map_err(db_err)?;
            return Ok(None);
        }
        let job = key.job_type.clone();
        let out = self.dispatcher.create_marked(&txn, key, now).await?;
        txn.advance(id, next).await?;
        txn.into_inner().commit().await.map_err(db_err)?;
        Ok(out.created.then_some((out.run.id, job)))
    }

    async fn locked(&self, db: &DatabaseConnection, now: DateTime<Utc>) -> AppResult<TickReport> {
        let d = &self.dispatcher;
        let mut report = TickReport::default();
        // Connections verified before delivery schedules existed get them here, before the due scan.
        let repo = Pg::new(db);
        if let Err(e) = repo.backfill_defaults(now).await {
            tracing::error!(error = %e, "schedule backfill failed");
        }
        for id in repo.due_ids(now).await? {
            // One bad schedule must not block the others; its transaction rolled back, so it is due again next tick.
            match self.due_schedule(db, id, now).await {
                Ok(Some((run, job))) => match d.dispatch(run, &job, now).await {
                    Ok(sent) => report.schedules_run += usize::from(sent),
                    Err(e) => {
                        tracing::error!(schedule = %id, %run, error = %e, "enqueue failed, the retry pass picks it up next tick")
                    }
                },
                Ok(None) => {}
                Err(e) => tracing::error!(schedule = %id, error = %e, "schedule failed"),
            }
        }
        report.retries_run = self.retry_pass(db, now).await?;
        Ok(report)
    }

    /// Runs parked with `schedule_retry` (status queued + next_attempt_at), and runs whose
    /// enqueue was interrupted after they were committed (the outbox marker). Deleted
    /// organisations get no more work: their due parked runs end `Skipped` (fenced, so a
    /// worker already holding a lease cannot revive one) instead of waiting forever. Returns
    /// how many were handed to a worker.
    async fn retry_pass(&self, db: &DatabaseConnection, now: DateTime<Utc>) -> AppResult<usize> {
        let due = Pg::new(db).due_runs(now).await?;
        let (gone, live): (Vec<_>, Vec<_>) = due.into_iter().partition(|r| r.organisation_deleted);
        let txn = Pg::new(db.begin().await.map_err(db_err)?);
        for r in gone {
            txn.skip_run(r.run_id, "org_deleted").await?;
        }
        txn.into_inner().commit().await.map_err(db_err)?;
        let mut sent_total = 0;
        for r in live {
            match self
                .dispatcher
                .dispatch(r.run_id, &r.job_type, r.marker)
                .await
            {
                Ok(sent) => sent_total += usize::from(sent),
                Err(e) => tracing::error!(run = %r.run_id, error = %e, "retry enqueue failed"),
            }
        }
        Ok(sent_total)
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::ConnectionTrait;

    use super::*;
    use crate::{
        actions::runs::test_support::FakeQueue,
        adapters::{db::ledger_storage::stmt, memory::MemStore},
    };

    #[tokio::test]
    async fn tick_with_lock_held_returns_none() {
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
        let other = Database::connect(url.clone()).await.unwrap();
        let held = other.begin().await.unwrap();
        held.execute_raw(stmt(
            "SELECT pg_advisory_xact_lock(hashtext('opsagent-scheduler'))",
            vec![],
        ))
        .await
        .unwrap();
        let store = Arc::new(MemStore::default());
        let dispatcher = Arc::new(RunDispatcher::new(store, Arc::new(FakeQueue::default())));
        let tick = SchedulerTick::new(url, dispatcher);
        assert_eq!(tick.run(Utc::now()).await.unwrap(), None);
        held.commit().await.unwrap();
    }
}
