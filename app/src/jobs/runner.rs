//! Drains the `jobs` table: at most `concurrency` jobs in flight, one poll every `poll` when
//! idle. A handler error or panic goes through `JobSource::fail` (retry backoff or Dead).
//! Full scans can run for hours, so at most `scan_slots` of them run at once and the other
//! slots always stay free for verifies, alerts and briefings.
use std::{
    collections::HashMap,
    future::Future,
    panic::AssertUnwindSafe,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
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

/// Full-scan slots: `requested`, but at least 1 and, with more than one slot, never all of them.
fn scan_slots(concurrency: usize, requested: usize) -> usize {
    let concurrency = concurrency.max(1);
    requested.clamp(1, concurrency.saturating_sub(1).max(1))
}

/// How often a running worker refreshes its job locks; well under `JOB_LOCK_MAX_AGE_SECS`.
const HEARTBEAT: Duration = Duration::from_secs(30);

pub struct WorkerRunner {
    source: Arc<dyn JobSource>,
    handlers: HashMap<JobKind, Arc<dyn JobHandler>>,
    worker_id: String,
    concurrency: usize,
    scan_slots: usize,
    scans: AtomicUsize,
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
            scan_slots: scan_slots(c.worker_concurrency, c.worker_scan_slots),
            scans: AtomicUsize::new(0),
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
        let scans_full = self.scans.load(Ordering::SeqCst) >= self.scan_slots;
        let kinds: Vec<JobKind> = self
            .handlers
            .keys()
            .copied()
            .filter(|k| !(scans_full && *k == JobKind::FullScan))
            .collect();
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
                    Err(e) => {
                        tracing::error!(job = %id, kind, %run, error = %e, "job done but not completed")
                    }
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
            Err(e) => {
                tracing::error!(job = %id, kind, %run, error = %e, "job failed and not recorded")
            }
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
        let beat = this.clone();
        let heartbeat = tokio::spawn(async move {
            let mut every = tokio::time::interval(HEARTBEAT);
            loop {
                every.tick().await;
                if let Err(e) = beat.source.heartbeat(&beat.worker_id).await {
                    tracing::warn!(worker = %beat.worker_id, error = %e, "job heartbeat failed");
                }
            }
        });
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
                    let scan = job.kind == JobKind::FullScan;
                    if scan {
                        this.scans.fetch_add(1, Ordering::SeqCst);
                    }
                    tasks.spawn(async move {
                        r.process(job).await;
                        if scan {
                            r.scans.fetch_sub(1, Ordering::SeqCst);
                        }
                        drop(slot);
                    });
                    continue;
                }
                Ok(None) => {}
                Err(e) => tracing::error!(worker = %this.worker_id, error = %e, "dequeue failed"),
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
        heartbeat.abort();
        let released = this.source.release_mine(&this.worker_id).await?;
        tracing::info!(worker = %this.worker_id, released, "worker stopped");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::scan_slots;

    #[test]
    fn scans_never_take_every_slot() {
        assert_eq!(scan_slots(4, 2), 2);
        assert_eq!(scan_slots(4, 9), 3);
        assert_eq!(scan_slots(4, 0), 1);
        assert_eq!(scan_slots(2, 2), 1);
        assert_eq!(scan_slots(1, 2), 1); // one slot: scans must still run
    }
}
