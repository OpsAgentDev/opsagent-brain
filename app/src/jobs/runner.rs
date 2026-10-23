//! Drains the `jobs` table: at most `concurrency` jobs in flight, one poll every `poll` when
//! idle. A handler error or panic goes through `JobSource::fail` (retry backoff or Dead).
use std::{
    collections::HashMap, future::Future, panic::AssertUnwindSafe, sync::Arc, time::Duration,
};

use futures::FutureExt;
use opsagent_core::repo::Clock;
use opsagent_ledger::{
    queue::{Job, JobFailure, JobSource},
    JobKind,
};
use tokio::{sync::Semaphore, task::JoinSet};
use uuid::Uuid;

use super::JobHandler;
use crate::{config::Config, error::AppResult};

pub struct WorkerRunner {
    source: Arc<dyn JobSource>,
    handlers: HashMap<JobKind, Arc<dyn JobHandler>>,
    worker_id: String,
    concurrency: usize,
    poll: Duration,
    lock_max_age: Duration,
    grace: Duration,
    clock: Arc<dyn Clock>,
}

impl WorkerRunner {
    /// A runner for `handlers` (one per kind) with the `WORKER_*` and `JOB_LOCK_MAX_AGE_SECS`
    /// settings of `c`. Its id, `{hostname}-{uuid v7}`, is also its lease owner.
    pub fn new(
        source: Arc<dyn JobSource>,
        handlers: Vec<Arc<dyn JobHandler>>,
        c: &Config,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let host =
            hostname::get().map_or_else(|_| "worker".into(), |h| h.to_string_lossy().into_owned());
        Self {
            source,
            handlers: handlers.into_iter().map(|h| (h.kind(), h)).collect(),
            worker_id: format!("{host}-{}", Uuid::now_v7()),
            concurrency: c.worker_concurrency.max(1),
            poll: Duration::from_millis(c.worker_poll_ms),
            lock_max_age: Duration::from_secs(c.job_lock_max_age_secs),
            grace: Duration::from_secs(c.worker_shutdown_grace_secs),
            clock,
        }
    }

    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    async fn dequeue(&self) -> AppResult<Option<Job>> {
        let kinds: Vec<JobKind> = self.handlers.keys().copied().collect();
        let job = self
            .source
            .dequeue(&self.worker_id, &kinds, self.lock_max_age);
        Ok(job.await?)
    }

    /// Runs `job`'s handler; success completes the job, an error or a panic fails it.
    async fn process(&self, job: Job) {
        let (id, kind, run) = (job.id, job.kind.as_str(), job.run_id);
        let handler = self.handlers[&job.kind].clone();
        let out = AssertUnwindSafe(handler.handle(run)).catch_unwind().await;
        let error = match out {
            Ok(Ok(())) => {
                match self.source.complete(&job).await {
                    Ok(true) => {}
                    Ok(false) => tracing::warn!(job = %id, kind, %run, "job done, lock lost"),
                    Err(_) => tracing::error!(job = %id, kind, %run, "job done but not completed"),
                }
                return;
            }
            Ok(Err(e)) => e.to_string(),
            Err(_) => "handler panicked".to_owned(),
        };
        match self.source.fail(&job, &error, self.clock.now()).await {
            Ok(JobFailure::LockLost) => {
                tracing::warn!(job = %id, kind, %run, "job failed, lock lost")
            }
            Ok(outcome) => tracing::warn!(job = %id, kind, %run, ?outcome, "job failed"),
            Err(_) => tracing::error!(job = %id, kind, %run, "job failed and not recorded"),
        }
    }

    /// Test support: dequeues and handles due jobs one at a time until none is left.
    pub async fn drain(&self) -> AppResult<usize> {
        let mut n = 0;
        while let Some(job) = self.dequeue().await? {
            self.process(job).await;
            n += 1;
        }
        Ok(n)
    }

    /// Polls until `shutdown`; then stops dequeuing, gives in-flight jobs `grace` to finish,
    /// drops the rest and unlocks this worker's jobs without counting their attempt.
    pub async fn run(self, shutdown: impl Future<Output = ()>) -> AppResult<()> {
        let this = Arc::new(self);
        let slots = Arc::new(Semaphore::new(this.concurrency));
        let mut tasks = JoinSet::new();
        tokio::pin!(shutdown);
        loop {
            while tasks.try_join_next().is_some() {}
            let slot = tokio::select! {
                () = &mut shutdown => break,
                slot = slots.clone().acquire_owned() => slot.expect("semaphore is never closed"),
            };
            match this.dequeue().await {
                Ok(Some(job)) => {
                    let r = this.clone();
                    tasks.spawn(async move {
                        r.process(job).await;
                        drop(slot);
                    });
                    continue;
                }
                Ok(None) => {}
                Err(_) => tracing::error!(worker = %this.worker_id, "dequeue failed"),
            }
            drop(slot);
            tokio::select! {
                () = &mut shutdown => break,
                () = tokio::time::sleep(this.poll) => {}
            }
        }
        let finished = tokio::time::timeout(this.grace, async {
            while tasks.join_next().await.is_some() {}
        });
        if finished.await.is_err() {
            tracing::warn!(worker = %this.worker_id, left = tasks.len(), "grace over, dropping jobs");
            tasks.shutdown().await;
        }
        let released = this.source.release_mine(&this.worker_id).await?;
        tracing::info!(worker = %this.worker_id, released, "worker stopped");
        Ok(())
    }
}
