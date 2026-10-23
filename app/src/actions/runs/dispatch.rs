//! Creating runs and handing them to the queue (jobs.md). A new run carries the outbox marker
//! (`next_attempt_at`) until its enqueue is confirmed, so an enqueue lost to a crash or a
//! queue error is picked up again by the scheduler's retry pass.
use std::sync::Arc;

use chrono::{DateTime, Utc};
use opsagent_core::run::RunKey;
use opsagent_ledger::{CreateRunOutcome, JobKind, NewJob, Queue};
use uuid::Uuid;

use crate::{
    actions::uow::{Tx, UnitOfWork},
    error::AppResult,
};

pub struct RunDispatcher {
    uow: Arc<dyn UnitOfWork>,
    queue: Arc<dyn Queue>,
}

impl RunDispatcher {
    pub fn new(uow: Arc<dyn UnitOfWork>, queue: Arc<dyn Queue>) -> Self {
        Self { uow, queue }
    }

    /// Create the run (outbox marker on a new run) in `tx`; caller commits, then calls `hand_off`.
    pub async fn create_marked(
        &self,
        tx: &dyn Tx,
        key: RunKey,
        now: DateTime<Utc>,
    ) -> AppResult<CreateRunOutcome> {
        let out = tx.ledger().create_run(key).await?;
        if out.created {
            tx.ledger().mark_enqueue_pending(out.run.id, now).await?;
        }
        Ok(out)
    }

    /// After commit: enqueue, clear exactly `marker`; failure logged, marker left for the retry pass.
    pub async fn hand_off(&self, out: &CreateRunOutcome, marker: DateTime<Utc>) {
        let (run, job_type) = (out.run.id, out.run.key.job_type.as_str());
        if let Err(e) = self.dispatch(run, job_type, marker).await {
            tracing::error!(%run, job_type, error = %e, "enqueue failed, the retry pass picks it up");
        }
    }

    /// create_marked on its own transaction + hand_off; a duplicate key is the run already
    /// handed off. A failed hand-off is logged, not returned: the run is recorded.
    pub async fn enqueue(&self, key: RunKey, now: DateTime<Utc>) -> AppResult<CreateRunOutcome> {
        let tx = self.uow.begin().await?;
        let out = self.create_marked(&*tx, key, now).await?;
        tx.commit().await?;
        if out.created {
            self.hand_off(&out, now).await;
        }
        Ok(out)
    }

    /// Retry pass entry: enqueue and clear the marker; Ok(false) for an unknown job type.
    /// Only the exact `marker` is cleared, so a retry time a worker has since written survives.
    pub async fn dispatch(
        &self,
        run_id: Uuid,
        job_type: &str,
        marker: DateTime<Utc>,
    ) -> AppResult<bool> {
        let sent = match JobKind::parse(job_type) {
            Some(kind) => {
                let job = NewJob {
                    kind,
                    run_id,
                    run_at: marker,
                };
                self.queue.enqueue(job).await?;
                true
            }
            None => {
                tracing::warn!(job_type, %run_id, "no worker registered, not enqueued");
                false
            }
        };
        self.uow
            .ledger()
            .clear_enqueue_marker(run_id, marker)
            .await?;
        Ok(sent)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::{
        actions::{runs::test_support::FakeQueue, uow::Repos},
        adapters::memory::MemStore,
    };

    fn key(job_type: &str, now: DateTime<Utc>) -> RunKey {
        RunKey {
            organisation_id: Some(Uuid::new_v4()),
            connection_id: None,
            job_type: job_type.into(),
            scheduled_at: now,
        }
    }

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn dispatch_unknown_job_type_returns_false_and_logs() {
        let (store, queue) = (MemStore::default(), Arc::new(FakeQueue::default()));
        let d = RunDispatcher::new(Arc::new(store.clone()), queue.clone());
        let now = Utc::now();
        let run = store.ledger().create_run(key("no_worker", now)).await;
        let id = run.unwrap().run.id;
        store.ledger().mark_enqueue_pending(id, now).await.unwrap();
        let buf = Buf::default();
        let sub = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer({
                let b = buf.clone();
                move || b.clone()
            })
            .finish();
        let sent = {
            let _g = tracing::subscriber::set_default(sub);
            d.dispatch(id, "no_worker", now).await.unwrap()
        };
        assert!(!sent);
        assert!(queue.sent().is_empty());
        // The marker is cleared all the same: there is nothing to retry.
        assert!(!store.ledger().clear_enqueue_marker(id, now).await.unwrap());
        let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(out.contains("no worker registered"), "{out}");
        assert!(out.contains("no_worker"), "{out}");
    }

    #[tokio::test]
    async fn hand_off_failure_leaves_marker() {
        let store = MemStore::default();
        let d = RunDispatcher::new(Arc::new(store.clone()), Arc::new(FakeQueue::failing()));
        let now = Utc::now();
        let out = d.enqueue(key("verify", now), now).await.unwrap();
        assert!(out.created);
        // The run is recorded and still carries exactly the marker the retry pass looks for.
        let marked = store.ledger().clear_enqueue_marker(out.run.id, now).await;
        assert!(marked.unwrap());
    }

    #[tokio::test]
    async fn enqueue_sends_the_job_and_clears_the_marker_once() {
        let (store, queue) = (MemStore::default(), Arc::new(FakeQueue::default()));
        let d = RunDispatcher::new(Arc::new(store.clone()), queue.clone());
        let now = Utc::now();
        let out = d.enqueue(key("full_scan", now), now).await.unwrap();
        let again = d.enqueue(out.run.key.clone(), now).await.unwrap();
        assert!(!again.created);
        let job = NewJob {
            kind: JobKind::FullScan,
            run_id: out.run.id,
            run_at: now,
        };
        assert_eq!(queue.sent(), vec![job]);
        assert!(!store
            .ledger()
            .clear_enqueue_marker(out.run.id, now)
            .await
            .unwrap());
    }
}
