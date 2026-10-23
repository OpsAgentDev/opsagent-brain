//! `PgQueue` contracts (Pg only: the queue's guarantees are Postgres locking), plus the
//! in-memory `Tx::queue` used by action tests.
use std::{
    collections::HashSet,
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

use chrono::{DateTime, SubsecRound, Utc};
use opsagent_brain::{
    actions::uow::{Repos, UnitOfWork},
    adapters::{db::Pg, memory::MemStore, pg_queue::PgQueue},
};
use opsagent_core::run::{RunKey, RunStatus};
use opsagent_ledger::{
    queue::{Job, JobFailure, JobSource},
    JobKind, LedgerError, NewJob, Queue,
};
use sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement};
use serial_test::serial;
use uuid::Uuid;

use super::{org_id, PgSeed, Seed};

const AGE: Duration = Duration::from_secs(3600);
const ALL: &[JobKind] = &JobKind::ALL;

struct Lane {
    store: Pg,
    q: PgQueue<DatabaseConnection>,
    seed: PgSeed,
    org: Uuid,
    conn: Uuid,
    runs: AtomicU32,
}

async fn lane() -> Lane {
    let store = super::pg().await;
    let q = PgQueue(store.db().clone());
    let seed = PgSeed::new().await;
    let org = org_id(&store, "q").await;
    let conn = seed.connection(org).await;
    Lane {
        store,
        q,
        seed,
        org,
        conn,
        runs: AtomicU32::new(0),
    }
}

fn new_job(kind: JobKind, run_id: Uuid, run_at: DateTime<Utc>) -> NewJob {
    NewJob {
        kind,
        run_id,
        run_at,
    }
}

impl Lane {
    /// A run created through the ledger, as the dispatcher does.
    async fn run(&self) -> Uuid {
        let n = self.runs.fetch_add(1, Ordering::Relaxed);
        let key = RunKey {
            organisation_id: Some(self.org),
            connection_id: Some(self.conn),
            job_type: "full_scan".into(),
            scheduled_at: Utc::now().trunc_subsecs(0) + chrono::Duration::minutes(n.into()),
        };
        self.store.ledger().create_run(key).await.unwrap().run.id
    }

    /// A run with a job of `kind` due now; returns the run id.
    async fn job(&self, kind: JobKind) -> Uuid {
        let run = self.run().await;
        self.q
            .enqueue(new_job(kind, run, Utc::now()))
            .await
            .unwrap();
        run
    }

    async fn sql(&self, sql: &str) -> Vec<sea_orm::QueryResult> {
        let raw = Statement::from_string(DbBackend::Postgres, sql);
        // The seed's own connection: the app pool has one connection.
        self.seed.raw().query_all_raw(raw).await.unwrap()
    }

    async fn count(&self) -> i64 {
        self.sql("SELECT count(*) AS n FROM jobs").await[0]
            .try_get("", "n")
            .unwrap()
    }

    async fn dequeue(&self, worker: &str) -> Option<Job> {
        self.q.dequeue(worker, ALL, AGE).await.unwrap()
    }
}

#[tokio::test]
#[serial]
async fn enqueue_in_rolled_back_tx_leaves_no_job() {
    let l = lane().await;
    let run = l.run().await;
    let tx = l.store.begin().await.unwrap();
    tx.queue()
        .enqueue(new_job(JobKind::FullScan, run, Utc::now()))
        .await
        .unwrap();
    drop(tx);
    assert_eq!(l.count().await, 0);
    let tx = l.store.begin().await.unwrap();
    tx.queue()
        .enqueue(new_job(JobKind::FullScan, run, Utc::now()))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let job = l.dequeue("w1").await.unwrap();
    assert_eq!(
        (job.kind, job.run_id, job.attempts, job.max_attempts),
        (JobKind::FullScan, run, 1, 5)
    );
    let args: serde_json::Value = l.sql("SELECT args FROM jobs").await[0]
        .try_get("", "args")
        .unwrap();
    assert_eq!(args, serde_json::json!({ "run_id": run }));
}

#[tokio::test]
#[serial]
async fn enqueue_twice_for_one_run_keeps_one_job() {
    let l = lane().await;
    let run = l.job(JobKind::Verify).await;
    l.q.enqueue(new_job(JobKind::Verify, run, Utc::now()))
        .await
        .unwrap();
    // A duplicate inside a transaction is a no-op, not an error that aborts it.
    let tx = l.store.begin().await.unwrap();
    tx.queue()
        .enqueue(new_job(JobKind::Verify, run, Utc::now()))
        .await
        .unwrap();
    tx.ledger().load_run(run).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(l.count().await, 1);
}

#[tokio::test]
#[serial]
async fn two_concurrent_dequeues_never_get_the_same_job() {
    let l = lane().await;
    for _ in 0..20 {
        l.job(JobKind::FullScan).await;
    }
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let other = PgQueue(Database::connect(url).await.unwrap());
    async fn drain(q: &PgQueue<DatabaseConnection>, w: &str) -> Vec<Uuid> {
        let mut got = Vec::new();
        while let Some(j) = q.dequeue(w, ALL, AGE).await.unwrap() {
            got.push(j.id);
            tokio::task::yield_now().await;
        }
        got
    }
    let (a, b) = tokio::join!(drain(&l.q, "a"), drain(&other, "b"));
    let (sa, sb): (HashSet<_>, HashSet<_>) = (a.iter().collect(), b.iter().collect());
    assert_eq!(
        (sa.len(), sb.len()),
        (a.len(), b.len()),
        "a worker got one job twice"
    );
    assert!(!a.is_empty() && !b.is_empty(), "both workers got work");
    assert_eq!(sa.intersection(&sb).count(), 0);
    assert_eq!(sa.union(&sb).count(), 20);
}

#[tokio::test]
#[serial]
async fn future_run_at_not_dequeued() {
    let l = lane().await;
    let run = l.run().await;
    let later = Utc::now() + chrono::Duration::hours(1);
    l.q.enqueue(new_job(JobKind::Verify, run, later))
        .await
        .unwrap();
    assert!(l.dequeue("w1").await.is_none());
    assert_eq!(l.count().await, 1);
}

#[tokio::test]
#[serial]
async fn kinds_filter_respected() {
    let l = lane().await;
    let run = l.job(JobKind::Verify).await;
    let kinds = [JobKind::FullScan, JobKind::DeliverBriefing];
    assert!(l.q.dequeue("w1", &kinds, AGE).await.unwrap().is_none());
    let job =
        l.q.dequeue("w1", &[JobKind::FullScan, JobKind::Verify], AGE)
            .await
            .unwrap();
    assert_eq!(job.map(|j| j.run_id), Some(run));
}

#[tokio::test]
#[serial]
async fn complete_deletes_row() {
    let l = lane().await;
    l.job(JobKind::DeliverWeekly).await;
    let job = l.dequeue("w1").await.unwrap();
    l.q.complete(job.id).await.unwrap();
    assert_eq!(l.count().await, 0);
}

#[tokio::test]
#[serial]
async fn fail_with_attempts_left_unlocks_and_backs_off_one_minute() {
    let l = lane().await;
    l.job(JobKind::Verify).await;
    let job = l.dequeue("w1").await.unwrap();
    let now = Utc::now().trunc_subsecs(0);
    let at = now + chrono::Duration::minutes(1);
    assert_eq!(
        l.q.fail(&job, "boom", now).await.unwrap(),
        JobFailure::Retrying { at }
    );
    let r = &l
        .sql("SELECT run_at, locked_at, locked_by, last_error FROM jobs")
        .await[0];
    assert_eq!(r.try_get::<DateTime<Utc>>("", "run_at").unwrap(), at);
    assert!(r
        .try_get::<Option<DateTime<Utc>>>("", "locked_at")
        .unwrap()
        .is_none());
    assert!(r
        .try_get::<Option<String>>("", "locked_by")
        .unwrap()
        .is_none());
    assert_eq!(
        r.try_get::<Option<String>>("", "last_error")
            .unwrap()
            .as_deref(),
        Some("boom")
    );
    // Not due until the backoff has passed.
    assert!(l.dequeue("w1").await.is_none());
}

#[tokio::test]
#[serial]
async fn fail_on_last_attempt_marks_run_failed_and_keeps_row() {
    let l = lane().await;
    let run = l.job(JobKind::FullScan).await;
    l.sql("UPDATE jobs SET attempts = 4").await;
    let job = l.dequeue("w1").await.unwrap();
    assert_eq!(job.attempts, 5);
    // A worker still holding the old lease (fence) when the job goes dead.
    let stale = l.store.ledger().bump_fence(run).await.unwrap();
    let running = RunStatus::Running;
    l.store
        .ledger()
        .set_status(run, stale, running, None)
        .await
        .unwrap();
    assert_eq!(
        l.q.fail(&job, "boom", Utc::now()).await.unwrap(),
        JobFailure::Dead
    );
    let late = l
        .store
        .ledger()
        .set_status(run, stale, RunStatus::Done, None);
    assert!(matches!(late.await, Err(LedgerError::StaleFence)));
    l.assert_dead(run, "boom").await;
}

#[tokio::test]
#[serial]
async fn stale_lock_on_last_attempt_is_finalised_dead() {
    let l = lane().await;
    let run = l.job(JobKind::FullScan).await;
    l.sql("UPDATE jobs SET attempts = 4").await;
    l.dequeue("w1").await.unwrap();
    l.sql("UPDATE jobs SET locked_at = now() - interval '2 hours'")
        .await;
    assert!(l.dequeue("w2").await.is_none());
    l.assert_dead(run, "lock_expired").await;
}

impl Lane {
    /// The job stays locked with no owner and `error`; the run failed once; nothing revives it.
    async fn assert_dead(&self, run: Uuid, error: &str) {
        assert_eq!(self.q.release_mine("w1").await.unwrap(), 0);
        let row = self.store.ledger().load_run(run).await.unwrap();
        assert_eq!(row.status, RunStatus::Failed);
        assert_eq!(
            row.partial_reason.as_deref(),
            Some("job_attempts_exhausted")
        );
        let n = "SELECT count(*) AS n FROM jobs WHERE locked_at IS NOT NULL AND locked_by IS NULL \
                 AND attempts = 5 AND last_error = '";
        let n: i64 = self.sql(&format!("{n}{error}'")).await[0]
            .try_get("", "n")
            .unwrap();
        assert_eq!(n, 1);
        assert!(self
            .q
            .dequeue("w2", ALL, Duration::ZERO)
            .await
            .unwrap()
            .is_none());
    }
}

#[tokio::test]
#[serial]
async fn stale_lock_is_dequeued_again() {
    let l = lane().await;
    l.job(JobKind::FullScan).await;
    let first = l.dequeue("w1").await.unwrap();
    assert!(l.dequeue("w2").await.is_none(), "a fresh lock is not free");
    l.sql("UPDATE jobs SET locked_at = now() - interval '2 hours'")
        .await;
    let again = l.dequeue("w2").await.unwrap();
    assert_eq!((again.id, again.attempts), (first.id, 2));
    let by: String = l.sql("SELECT locked_by FROM jobs").await[0]
        .try_get("", "locked_by")
        .unwrap();
    assert_eq!(by, "w2");
}

#[tokio::test]
#[serial]
async fn release_mine_unlocks_only_own_rows() {
    let l = lane().await;
    l.job(JobKind::FullScan).await;
    l.job(JobKind::FullScan).await;
    let mine = l.dequeue("w1").await.unwrap();
    let theirs = l.dequeue("w2").await.unwrap();
    assert_eq!(l.q.release_mine("w1").await.unwrap(), 1);
    let next = l.dequeue("w3").await.unwrap();
    // The interrupted attempt does not count against the job.
    assert_eq!((next.id, next.attempts), (mine.id, 1));
    assert_ne!(next.id, theirs.id);
    assert!(l.dequeue("w3").await.is_none());
}

#[tokio::test]
async fn mem_tx_enqueue_visible_only_after_commit() {
    let s = MemStore::default();
    let job = new_job(JobKind::Verify, Uuid::now_v7(), Utc::now());
    let tx = s.begin().await.unwrap();
    tx.queue().enqueue(job.clone()).await.unwrap();
    drop(tx);
    assert!(s.jobs().is_empty());
    let tx = s.begin().await.unwrap();
    tx.queue().enqueue(job.clone()).await.unwrap();
    tx.queue().enqueue(job.clone()).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(s.jobs(), [job]);
}
