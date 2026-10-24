//! Creating runs and their jobs (app-shell.md, jobs): a new run's job is inserted on the run's
//! own transaction, so both commit or neither does, and an enqueue failure is the caller's
//! error. The unique index on `jobs.run_id` makes a second job for a run a no-op.
use std::sync::Arc;

use chrono::{DateTime, Utc};
use opsagent_core::run::RunKey;
use opsagent_ledger::{CreateRunOutcome, JobKind, NewJob};
use uuid::Uuid;

use crate::{
    actions::uow::{Tx, UnitOfWork},
    error::AppResult,
};

pub struct RunDispatcher {
    uow: Arc<dyn UnitOfWork>,
}

/// The job for `run_id`, or `None` (logged) for a job type no worker handles.
fn job(run_id: Uuid, job_type: &str, run_at: DateTime<Utc>) -> Option<NewJob> {
    let Some(kind) = JobKind::parse(job_type) else {
        tracing::warn!(job_type, %run_id, "no worker registered, not enqueued");
        return None;
    };
    Some(NewJob {
        kind,
        run_id,
        run_at,
    })
}

impl RunDispatcher {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    /// Create the run and, if new, its job, on `tx` (one commit). Duplicate key: no job.
    pub async fn create_and_enqueue(
        &self,
        tx: &dyn Tx,
        key: RunKey,
        now: DateTime<Utc>,
    ) -> AppResult<CreateRunOutcome> {
        let out = tx.ledger().create_run(key).await?;
        if out.created {
            if let Some(j) = job(out.run.id, &out.run.key.job_type, now) {
                tx.queue().enqueue(j).await?;
            }
        }
        Ok(out)
    }

    /// `create_and_enqueue` on its own transaction.
    pub async fn enqueue(&self, key: RunKey, now: DateTime<Utc>) -> AppResult<CreateRunOutcome> {
        let tx = self.uow.begin().await?;
        let out = self.create_and_enqueue(&*tx, key, now).await?;
        tx.commit().await?;
        Ok(out)
    }

    /// Retry pass: in one tx, insert the job (the unique index makes a second one a no-op),
    /// then clear exactly `marker`, so a retry time a worker has since written survives.
    /// `Ok(false)` for an unknown job type, whose marker is cleared all the same.
    pub async fn requeue(
        &self,
        run_id: Uuid,
        job_type: &str,
        marker: DateTime<Utc>,
    ) -> AppResult<bool> {
        let tx = self.uow.begin().await?;
        let j = job(run_id, job_type, marker);
        let sent = j.is_some();
        if let Some(j) = j {
            tx.queue().enqueue(j).await?;
        }
        tx.ledger().clear_enqueue_marker(run_id, marker).await?;
        tx.commit().await?;
        Ok(sent)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::{actions::uow::Repos, adapters::memory::MemStore};

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
    async fn requeue_unknown_job_type_returns_false_and_logs() {
        let store = MemStore::default();
        let d = RunDispatcher::new(Arc::new(store.clone()));
        let now = Utc::now();
        let run = store.ledger().create_run(key("no_worker", now)).await;
        let id = run.unwrap().run.id;
        store.ledger().schedule_retry(id, 0, now).await.unwrap();
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
            d.requeue(id, "no_worker", now).await.unwrap()
        };
        assert!(!sent);
        assert!(store.jobs().is_empty());
        // The marker is cleared all the same: there is nothing to retry.
        assert!(!store.ledger().clear_enqueue_marker(id, now).await.unwrap());
        let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(out.contains("no worker registered"), "{out}");
        assert!(out.contains("no_worker"), "{out}");
    }

    #[tokio::test]
    async fn enqueue_sends_the_job_once() {
        let store = MemStore::default();
        let d = RunDispatcher::new(Arc::new(store.clone()));
        let now = Utc::now();
        let out = d.enqueue(key("full_scan", now), now).await.unwrap();
        let again = d.enqueue(out.run.key.clone(), now).await.unwrap();
        assert!(!again.created);
        let job = NewJob {
            kind: JobKind::FullScan,
            run_id: out.run.id,
            run_at: now,
        };
        assert_eq!(store.jobs(), vec![job]);
        // No outbox marker is ever written.
        assert!(!store
            .ledger()
            .clear_enqueue_marker(out.run.id, now)
            .await
            .unwrap());
    }
}
