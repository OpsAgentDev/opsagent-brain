//! `WorkerRunner` over the Postgres queue: kinds, concurrency, retries, shutdown, stale locks.
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering::SeqCst},
        Arc, Mutex,
    },
    time::Duration,
};

use async_trait::async_trait;
use opsagent_brain::{
    adapters::{
        db::ledger_storage::{stmt, PgStorage},
        pg_queue::PgQueue,
    },
    config::Config,
    error::{AppError, AppResult},
    jobs::{JobHandler, WorkerRunner},
};
use opsagent_core::run::{RunKey, RunStatus};
use opsagent_ledger::{
    run_chunked, Checkpoint, ChunkOutcome, JobKind, LedgerError, NewJob, Queue, RunChunkedOptions,
    Storage,
};
use sea_orm::{ConnectionTrait, QueryResult};
use serial_test::serial;
use tokio::sync::Notify;
use uuid::Uuid;

use crate::support::TestApp;

async fn new_run(ctx: &TestApp, n: i64) -> Uuid {
    let key = RunKey {
        organisation_id: None,
        connection_id: None,
        job_type: "verify".into(),
        scheduled_at: chrono::DateTime::from_timestamp(1_800_000_000 + n * 60, 0).unwrap(),
    };
    let storage = PgStorage::new(ctx.db.clone());
    storage.create_run(key).await.unwrap().run.id
}

async fn enqueue(ctx: &TestApp, kind: JobKind, run_id: Uuid) {
    let run_at = chrono::Utc::now();
    let job = NewJob {
        kind,
        run_id,
        run_at,
    };
    PgQueue(ctx.db.clone()).enqueue(job).await.unwrap();
}

fn runner(
    ctx: &TestApp,
    handlers: Vec<Arc<dyn JobHandler>>,
    f: impl FnOnce(&mut Config),
) -> WorkerRunner {
    let mut c = ctx.state.config.clone();
    f(&mut c);
    let source = Arc::new(PgQueue(ctx.db.clone()));
    WorkerRunner::new(source, handlers, &c, ctx.state.clock.clone())
}

async fn job_row(ctx: &TestApp, run: Uuid) -> Option<QueryResult> {
    // `ahead`: seconds until the job is due.
    let q = "SELECT attempts, locked_at IS NOT NULL AS locked, locked_by, last_error, \
             EXTRACT(EPOCH FROM run_at - now())::float8 AS ahead FROM jobs WHERE run_id = $1";
    ctx.db
        .query_one_raw(stmt(q, vec![run.into()]))
        .await
        .unwrap()
}

/// Records each run it handles.
struct Rec(JobKind, Mutex<Vec<Uuid>>);

#[async_trait]
impl JobHandler for Rec {
    fn kind(&self) -> JobKind {
        self.0
    }
    async fn handle(&self, run_id: Uuid) -> AppResult<()> {
        self.1.lock().unwrap().push(run_id);
        Ok(())
    }
}

#[tokio::test]
#[serial]
async fn runner_handles_each_kind_once() {
    let ctx = TestApp::boot().await;
    let recs: Vec<Arc<Rec>> = JobKind::ALL
        .map(|k| Arc::new(Rec(k, Mutex::default())))
        .into();
    let mut runs = Vec::new();
    for (i, k) in JobKind::ALL.into_iter().enumerate() {
        let run = new_run(&ctx, i as i64).await;
        enqueue(&ctx, k, run).await;
        runs.push(run);
    }
    let handlers = recs
        .iter()
        .map(|r| r.clone() as Arc<dyn JobHandler>)
        .collect();
    let w = runner(&ctx, handlers, |_| {});
    assert_eq!(w.drain().await.unwrap(), 4);
    for (rec, run) in recs.iter().zip(&runs) {
        assert_eq!(*rec.1.lock().unwrap(), vec![*run], "{:?}", rec.0);
        assert!(
            job_row(&ctx, *run).await.is_none(),
            "completed jobs are deleted"
        );
    }
    assert_eq!(w.drain().await.unwrap(), 0);
}

/// Holds each job for a while, counting how many run at once.
#[derive(Default)]
struct Slow {
    now: AtomicUsize,
    max: AtomicUsize,
    done: AtomicUsize,
}

#[async_trait]
impl JobHandler for Slow {
    fn kind(&self) -> JobKind {
        JobKind::FullScan
    }
    async fn handle(&self, _: Uuid) -> AppResult<()> {
        let n = self.now.fetch_add(1, SeqCst) + 1;
        self.max.fetch_max(n, SeqCst);
        tokio::time::sleep(Duration::from_millis(100)).await;
        self.now.fetch_sub(1, SeqCst);
        self.done.fetch_add(1, SeqCst);
        Ok(())
    }
}

#[tokio::test]
#[serial]
async fn runner_respects_concurrency() {
    let ctx = TestApp::boot().await;
    for i in 0..6 {
        enqueue(&ctx, JobKind::FullScan, new_run(&ctx, i).await).await;
    }
    let slow = Arc::new(Slow::default());
    let w = runner(&ctx, vec![slow.clone()], |c| {
        c.worker_concurrency = 2;
        c.worker_poll_ms = 10;
    });
    let s = slow.clone();
    let all_done = async move {
        while s.done.load(SeqCst) < 6 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    let ran = tokio::time::timeout(Duration::from_secs(20), w.run(all_done)).await;
    ran.expect("runner stops").unwrap();
    assert_eq!(slow.max.load(SeqCst), 2, "two at once, never more");
}

struct Fails(JobKind);

#[async_trait]
impl JobHandler for Fails {
    fn kind(&self) -> JobKind {
        self.0
    }
    async fn handle(&self, _: Uuid) -> AppResult<()> {
        if self.0 == JobKind::FullScan {
            panic!("handler bug");
        }
        Err(AppError::Internal("boom".into()))
    }
}

#[tokio::test]
#[serial]
async fn handler_error_is_retried_by_job_backoff() {
    let ctx = TestApp::boot().await;
    let (erring, panicking) = (new_run(&ctx, 0).await, new_run(&ctx, 1).await);
    enqueue(&ctx, JobKind::Verify, erring).await;
    enqueue(&ctx, JobKind::FullScan, panicking).await;
    let handlers: Vec<Arc<dyn JobHandler>> = vec![
        Arc::new(Fails(JobKind::Verify)),
        Arc::new(Fails(JobKind::FullScan)),
    ];
    let w = runner(&ctx, handlers, |_| {});
    // A panic is an error like any other: the runner carries on.
    assert_eq!(w.drain().await.unwrap(), 2);
    for (run, error) in [(erring, "internal: boom"), (panicking, "handler panicked")] {
        let r = job_row(&ctx, run).await.expect("kept for a retry");
        assert_eq!(r.try_get::<i32>("", "attempts").unwrap(), 1);
        assert!(!r.try_get::<bool>("", "locked").unwrap());
        assert_eq!(
            r.try_get::<Option<String>>("", "last_error")
                .unwrap()
                .as_deref(),
            Some(error)
        );
        // First retry: one minute out (`retry::backoff(0)`).
        let ahead: f64 = r.try_get("", "ahead").unwrap();
        assert!((50.0..=61.0).contains(&ahead), "{ahead}");
    }
    assert_eq!(w.drain().await.unwrap(), 0, "not due yet");
}

/// Never finishes; says when it started.
struct Hangs(Notify);

#[async_trait]
impl JobHandler for Hangs {
    fn kind(&self) -> JobKind {
        JobKind::Verify
    }
    async fn handle(&self, _: Uuid) -> AppResult<()> {
        self.0.notify_one();
        std::future::pending().await
    }
}

#[tokio::test]
#[serial]
async fn shutdown_releases_own_locks_and_returns() {
    let ctx = TestApp::boot().await;
    let run = new_run(&ctx, 0).await;
    enqueue(&ctx, JobKind::Verify, run).await;
    let hangs = Arc::new(Hangs(Notify::new()));
    let w = runner(&ctx, vec![hangs.clone()], |c| {
        c.worker_poll_ms = 10;
        c.worker_shutdown_grace_secs = 0;
    });
    let id = w.worker_id().to_owned();
    // `{hostname}-{uuid v7}`
    let (host, uuid) = id.split_at(id.len() - 37);
    assert!(!host.is_empty(), "{id}");
    assert_eq!(
        Uuid::parse_str(&uuid[1..]).unwrap().get_version_num(),
        7,
        "{id}"
    );
    let h = hangs.clone();
    let started = async move { h.0.notified().await };
    let ran = tokio::time::timeout(Duration::from_secs(10), w.run(started)).await;
    ran.expect("shutdown returns").unwrap();
    let r = job_row(&ctx, run).await.expect("job kept");
    assert!(!r.try_get::<bool>("", "locked").unwrap());
    assert_eq!(r.try_get::<Option<String>>("", "locked_by").unwrap(), None);
    // The interrupted attempt is not counted.
    assert_eq!(r.try_get::<i32>("", "attempts").unwrap(), 0);
}

/// One chunk under the ledger lease. The first call (worker A) takes a short lease, never
/// heartbeats and stalls inside its chunk until `gate`; later calls (worker B) run straight.
struct Gated {
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
            opts.lease_ttl = Duration::from_millis(300);
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

/// Review Focus 2: a stale job lock is taken over and the ledger fence keeps one outcome.
#[tokio::test]
#[serial]
async fn stale_lock_second_worker_wins_fence() {
    let ctx = TestApp::boot().await;
    let run = new_run(&ctx, 0).await;
    enqueue(&ctx, JobKind::FullScan, run).await;
    let gated = Arc::new(Gated {
        storage: PgStorage::new(ctx.db.clone()),
        redis: ctx.redis(),
        calls: AtomicUsize::new(0),
        entered: Notify::new(),
        gate: Notify::new(),
        a: Mutex::new(None),
    });
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
