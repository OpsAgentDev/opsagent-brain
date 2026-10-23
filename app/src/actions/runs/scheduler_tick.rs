//! `SchedulerTick`: enqueue due schedules and due retries, then advance `next_due_at`.
//! The scheduler holds no state; the unique run key makes a repeated tick a no-op (jobs.md).
use std::sync::Arc;

use chrono::{DateTime, Utc};
use opsagent_deliver::schedule::next_after;
use uuid::Uuid;

use super::RunDispatcher;
use crate::{actions::uow::UnitOfWork, error::AppResult};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct TickReport {
    /// Runs handed to a real worker (no-op job types and duplicates are not counted).
    pub schedules_run: usize,
    pub retries_run: usize,
}

pub struct SchedulerTick {
    /// The scheduler's own pool (boot): one connection holds the lock transaction for the
    /// whole tick, the other does the per-schedule work.
    uow: Arc<dyn UnitOfWork>,
    dispatcher: Arc<RunDispatcher>,
}

impl SchedulerTick {
    pub fn new(uow: Arc<dyn UnitOfWork>, dispatcher: Arc<RunDispatcher>) -> Self {
        Self { uow, dispatcher }
    }

    /// One tick at `now`. `None` when another scheduler holds the advisory lock.
    pub async fn run(&self, now: DateTime<Utc>) -> AppResult<Option<TickReport>> {
        // The transaction-level lock is released by commit/rollback/disconnect, never by us.
        let lock = self.uow.begin().await?;
        if !lock.schedules().try_lock_scheduler().await? {
            return Ok(None);
        }
        let report = self.locked(now).await;
        lock.commit().await?;
        report.map(Some)
    }

    /// One schedule, one transaction: lock, create the run, advance `next_due_at`, commit.
    /// Returns the run only when this call created it.
    async fn due_schedule(
        &self,
        id: Uuid,
        now: DateTime<Utc>,
    ) -> AppResult<Option<(Uuid, String)>> {
        let tx = self.uow.begin().await?;
        let Some((key, cron, tz)) = tx.schedules().lock_due(id, now).await? else {
            return Ok(None);
        };
        // Missed ticks collapse into this one run; the next slot is after `now` (PRD 7.3).
        let next = next_after(&cron, &tz, now);
        if next.is_none() {
            tracing::error!(schedule = %id, cron, tz, "invalid schedule, disabling");
            tx.schedules().advance(id, None).await?;
            tx.commit().await?;
            return Ok(None);
        }
        let job = key.job_type.clone();
        let out = self.dispatcher.create_marked(&*tx, key, now).await?;
        tx.schedules().advance(id, next).await?;
        tx.commit().await?;
        Ok(out.created.then_some((out.run.id, job)))
    }

    async fn locked(&self, now: DateTime<Utc>) -> AppResult<TickReport> {
        let d = &self.dispatcher;
        let mut report = TickReport::default();
        // Connections verified before delivery schedules existed get them here, before the due scan.
        let repo = self.uow.schedules();
        if let Err(e) = repo.backfill_defaults(now).await {
            tracing::error!(error = %e, "schedule backfill failed");
        }
        for id in repo.due_ids(now).await? {
            // One bad schedule must not block the others; its transaction rolled back, so it is due again next tick.
            match self.due_schedule(id, now).await {
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
        report.retries_run = self.retry_pass(now).await?;
        Ok(report)
    }

    /// Runs parked with `schedule_retry` (status queued + next_attempt_at), and runs whose
    /// enqueue was interrupted after they were committed (the outbox marker). Deleted
    /// organisations get no more work: their due parked runs end `Skipped` (fenced, so a
    /// worker already holding a lease cannot revive one) instead of waiting forever. Returns
    /// how many were handed to a worker.
    async fn retry_pass(&self, now: DateTime<Utc>) -> AppResult<usize> {
        let due = self.uow.schedules().due_runs(now).await?;
        let (gone, live): (Vec<_>, Vec<_>) = due.into_iter().partition(|r| r.organisation_deleted);
        let tx = self.uow.begin().await?;
        for r in gone {
            tx.ledger().skip_run(r.run_id, "org_deleted").await?;
        }
        tx.commit().await?;
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
    use sea_orm::{ConnectionTrait, Database, TransactionTrait};

    use super::*;
    use crate::{
        actions::runs::test_support::FakeQueue,
        adapters::{
            db::{ledger_storage::stmt, Pg},
            memory::MemStore,
        },
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
        let pool = Database::connect(url).await.unwrap();
        let tick = SchedulerTick::new(Arc::new(Pg::new(pool)), dispatcher);
        assert_eq!(tick.run(Utc::now()).await.unwrap(), None);
        held.commit().await.unwrap();
    }
}
