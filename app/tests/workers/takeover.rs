//! Takeover of a job another worker held: a stale lock, and a job released at shutdown.
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering::SeqCst},
        Arc, Mutex,
    },
    time::Duration,
};

use async_trait::async_trait;
use opsagent_brain::{
    adapters::db::ledger_storage::{stmt, PgStorage},
    error::AppResult,
    jobs::JobHandler,
};
use opsagent_core::run::RunStatus;
use opsagent_ledger::{
    run_chunked, Checkpoint, ChunkOutcome, JobKind, LedgerError, RunChunkedOptions, Storage,
};
use sea_orm::ConnectionTrait;
use serial_test::serial;
use tokio::sync::Notify;
use uuid::Uuid;

use super::runner::{enqueue, job_row, new_run, runner};
use crate::support::TestApp;

/// One chunk under the ledger lease. The first call (worker A) takes an `a_ttl` lease, never
/// heartbeats and stalls inside its chunk until `gate`; later calls (worker B) run straight.
struct Gated {
    a_ttl: Duration,
    storage: PgStorage,
    redis: opsagent_ledger::redis::Client,
    calls: AtomicUsize,
    entered: Notify,
    gate: Notify,
    a: Mutex<Option<(u64, RunStatus)>>,
}

#[async_trait]
impl JobHandler for Gated {
    fn kind(&self) -> JobKind {
        JobKind::FullScan
    }
    async fn handle(&self, run_id: Uuid) -> AppResult<()> {
        let first = self.calls.fetch_add(1, SeqCst) == 0;
        let mut opts = RunChunkedOptions::default();
        if first {
            opts.lease_ttl = self.a_ttl;
            opts.heartbeat_every = Duration::from_secs(3600);
        }
        let fence = Mutex::new(0);
        let chunks = vec!["only".to_owned()];
        let out = run_chunked(
            &self.storage,
            &self.redis,
            run_id,
            chunks,
            opts,
            |_, lease| {
                *fence.lock().unwrap() = lease.fence;
                async move {
                    if first {
                        self.entered.notify_one();
                        self.gate.notified().await;
                    }
                    Ok(ChunkOutcome::default())
                }
            },
        )
        .await?;
        if first {
            *self.a.lock().unwrap() = Some((*fence.lock().unwrap(), out));
        }
        Ok(())
    }
}

fn gated(ctx: &TestApp, a_ttl: Duration) -> Gated {
    Gated {
        a_ttl,
        storage: PgStorage::new(ctx.db.clone()),
        redis: ctx.redis(),
        calls: AtomicUsize::new(0),
        entered: Notify::new(),
        gate: Notify::new(),
        a: Mutex::new(None),
    }
}

/// Review Focus 2: a stale job lock is taken over and the ledger fence keeps one outcome.
#[tokio::test]
#[serial]
async fn stale_lock_second_worker_wins_fence() {
    let ctx = TestApp::boot().await;
    let run = new_run(&ctx, 0).await;
    enqueue(&ctx, JobKind::FullScan, run).await;
    let gated = Arc::new(gated(&ctx, Duration::from_millis(300)));
    let a = Arc::new(runner(&ctx, vec![gated.clone()], |_| {}));
    let b = runner(&ctx, vec![gated.clone()], |_| {});
    assert_ne!(a.worker_id(), b.worker_id());
    let a_drain = tokio::spawn({
        let a = a.clone();
        async move { a.drain().await }
    });
    // A holds the job and the lease, and stalls mid-chunk.
    gated.entered.notified().await;
    let r = job_row(&ctx, run).await.unwrap();
    assert_eq!(
        r.try_get::<Option<String>>("", "locked_by")
            .unwrap()
            .as_deref(),
        Some(a.worker_id())
    );
    // A's job lock ages past JOB_LOCK_MAX_AGE and its unrenewed lease lapses.
    let age = "UPDATE jobs SET locked_at = now() - interval '8 hours' WHERE run_id = $1";
    ctx.db
        .execute_raw(stmt(age, vec![run.into()]))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // B takes the stale job (a second attempt), bumps the fence and finishes the run.
    assert_eq!(b.drain().await.unwrap(), 1);
    assert!(job_row(&ctx, run).await.is_none());
    let storage = PgStorage::new(ctx.db.clone());
    assert_eq!(storage.load_run(run).await.unwrap().status, RunStatus::Done);

    // A wakes: its checkpoint write is rejected and it cannot change the outcome.
    gated.gate.notify_one();
    assert_eq!(a_drain.await.unwrap().unwrap(), 1);
    let (a_fence, a_out) = gated.a.lock().unwrap().take().expect("A finished its call");
    assert_eq!(a_out, RunStatus::Partial, "A gave up: lease lost");
    let write = storage
        .write_checkpoint(run, a_fence, &Checkpoint::default())
        .await;
    assert!(matches!(write, Err(LedgerError::StaleFence)), "{write:?}");
    let row = storage.load_run(run).await.unwrap();
    assert_eq!(row.status, RunStatus::Done, "exactly one terminal status");
    assert!(row.checkpoint.chunks_done.contains("only"));
    assert_eq!(gated.calls.load(SeqCst), 2);
}

/// Task 17 review I1: a job dropped at shutdown keeps its ledger lease for up to 120 s. Taken
/// again at once, it would meet `LeaseHeld`, be settled and deleted, and leave its run
/// `running` with no job. Released, it waits out the lease instead.
#[tokio::test]
#[serial]
async fn job_released_at_shutdown_runs_after_its_lease_lapses() {
    let ctx = TestApp::boot().await;
    let run = new_run(&ctx, 0).await;
    enqueue(&ctx, JobKind::FullScan, run).await;
    let gated = Arc::new(gated(&ctx, Duration::from_secs(120)));
    let a = runner(&ctx, vec![gated.clone()], |c| {
        c.worker_poll_ms = 10;
        c.worker_shutdown_grace_secs = 0;
    });
    let g = gated.clone();
    let entered = async move { g.entered.notified().await };
    let ran = tokio::time::timeout(Duration::from_secs(10), a.run(entered)).await;
    ran.expect("shutdown returns").unwrap();

    // The next worker finds nothing due while A's lease may still be live.
    let b = runner(&ctx, vec![gated.clone()], |_| {});
    assert_eq!(b.drain().await.unwrap(), 0);
    assert!(job_row(&ctx, run).await.is_some(), "job kept");

    // 150 s later: A's lease has expired and the job is due.
    let lease = format!("lease:{run}");
    let mut r = ctx.redis().get_connection().unwrap();
    let _: i64 = opsagent_ledger::redis::cmd("DEL")
        .arg(&lease)
        .query(&mut r)
        .unwrap();
    let due = "UPDATE jobs SET run_at = now() WHERE run_id = $1";
    ctx.db
        .execute_raw(stmt(due, vec![run.into()]))
        .await
        .unwrap();
    assert_eq!(b.drain().await.unwrap(), 1);
    assert!(job_row(&ctx, run).await.is_none());
    let row = PgStorage::new(ctx.db.clone()).load_run(run).await.unwrap();
    assert_eq!(row.status, RunStatus::Done, "exactly one terminal status");
    assert!(row.checkpoint.chunks_done.contains("only"));
    assert_eq!(gated.calls.load(SeqCst), 2);
}
