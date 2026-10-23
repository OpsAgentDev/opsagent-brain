mod common;
use opsagent_core::run::RunStatus;
use opsagent_ledger::harness::kill_after_each_checkpoint;
use opsagent_ledger::testing::MemoryStorage;
use opsagent_ledger::{
    effects::with_effect, lease::acquire, run_chunked, ChunkOutcome, RunChunkedOptions, Storage,
};
use serde_json::json;
use std::sync::atomic::{AtomicU32, Ordering::SeqCst};
use std::time::Duration;

fn opts(w: &str) -> RunChunkedOptions {
    RunChunkedOptions {
        worker_id: w.into(),
        lease_ttl: Duration::from_secs(5),
        heartbeat_every: Duration::from_millis(50),
        time_cap: Duration::from_secs(30),
        after_checkpoint: None,
    }
}

#[tokio::test]
async fn killed_after_each_checkpoint_resumes_with_effects_once() {
    let (r, s) = (common::redis(), MemoryStorage::default());
    let run = s.create_run(common::key()).await.unwrap().run;
    let counts: Vec<AtomicU32> = (0..3).map(|_| AtomicU32::new(0)).collect();
    let chunks: Vec<String> = (0..3).map(|i| format!("c{i}")).collect();
    let runs = kill_after_each_checkpoint(|kill| {
        let (r, s, counts, chunks) = (&r, &s, &counts, chunks.clone());
        async move {
            let mut o = opts("w");
            o.after_checkpoint = Some(kill);
            run_chunked(s, r, run.id, chunks, o, |c, _l| async move {
                let i: usize = c[1..].parse().unwrap();
                with_effect(s, run.id, &c, false, || async {
                    counts[i].fetch_add(1, SeqCst);
                    Ok(None)
                })
                .await?;
                Ok(ChunkOutcome {
                    stats: json!({ c.clone(): 1 }),
                    cursor: json!({ c.clone(): 2 }),
                })
            })
            .await
        }
    })
    .await
    .unwrap();
    assert_eq!(runs, 4); // one kill per chunk, then a run with nothing left
    assert!(counts.iter().all(|c| c.load(SeqCst) == 1));
    let row = s.load_run(run.id).await.unwrap();
    assert_eq!(row.status, RunStatus::Done);
    assert_eq!(row.checkpoint.stats, json!({"c0":1,"c1":1,"c2":1}));
    assert_eq!(row.checkpoint.cursor, json!({"c0":2,"c1":2,"c2":2}));
}

#[tokio::test]
async fn lease_lost_returns_partial() {
    let (r, s) = (common::redis(), MemoryStorage::default());
    let run = s.create_run(common::key()).await.unwrap().run;
    let st = run_chunked(
        &s,
        &r,
        run.id,
        vec!["a".into(), "b".into()],
        opts("w"),
        |_c, l| {
            let (r, s) = (r.clone(), &s);
            async move {
                // simulate expiry + takeover by another worker mid-chunk
                let mut c = r.get_multiplexed_async_connection().await.unwrap();
                let _: i32 = redis::cmd("DEL")
                    .arg(format!("lease:{}", l.run_id))
                    .query_async(&mut c)
                    .await
                    .unwrap();
                acquire(s, &r, l.run_id, "thief", Duration::from_secs(5))
                    .await
                    .unwrap()
                    .unwrap();
                Ok(ChunkOutcome::default())
            }
        },
    )
    .await
    .unwrap();
    assert_eq!(st, RunStatus::Partial);
    // stale holder cannot overwrite the thief's row
    assert_ne!(s.load_run(run.id).await.unwrap().status, RunStatus::Done);
}

#[tokio::test]
async fn time_cap_returns_partial() {
    let (r, s) = (common::redis(), MemoryStorage::default());
    let run = s.create_run(common::key()).await.unwrap().run;
    let mut o = opts("w");
    o.time_cap = Duration::from_millis(50);
    let st = run_chunked(
        &s,
        &r,
        run.id,
        vec!["a".into(), "b".into()],
        o,
        |_c, _l| async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok(ChunkOutcome::default())
        },
    )
    .await
    .unwrap();
    assert_eq!(st, RunStatus::Partial);
    assert_eq!(
        s.load_run(run.id).await.unwrap().partial_reason.as_deref(),
        Some("time_cap")
    );
}

#[tokio::test]
async fn kill_between_effect_done_and_checkpoint_runs_effect_once() {
    use std::sync::atomic::AtomicBool;
    let (r, s) = (common::redis(), MemoryStorage::default());
    let run = s.create_run(common::key()).await.unwrap().run;
    let (n, killed) = (AtomicU32::new(0), AtomicBool::new(false));
    let go = || {
        run_chunked(&s, &r, run.id, vec!["c0".into()], opts("w"), |c, _l| {
            let (n, killed, s) = (&n, &killed, &s);
            async move {
                with_effect(s, run.id, &c, false, || async {
                    n.fetch_add(1, SeqCst);
                    Ok(None)
                })
                .await?;
                if !killed.swap(true, SeqCst) {
                    return Err(opsagent_ledger::LedgerError::Killed); // effect done, no checkpoint
                }
                Ok(ChunkOutcome::default())
            }
        })
    };
    assert!(go().await.is_err());
    assert!(s
        .load_run(run.id)
        .await
        .unwrap()
        .checkpoint
        .chunks_done
        .is_empty());
    assert_eq!(go().await.unwrap(), RunStatus::Done);
    assert_eq!(n.load(SeqCst), 1);
    assert!(s
        .load_run(run.id)
        .await
        .unwrap()
        .checkpoint
        .chunks_done
        .contains("c0"));
}

#[tokio::test]
async fn dropping_run_chunked_stops_heartbeat() {
    let (r, s) = (common::redis(), MemoryStorage::default());
    let run = s.create_run(common::key()).await.unwrap().run;
    let mut o = opts("w");
    o.lease_ttl = Duration::from_millis(200);
    o.heartbeat_every = Duration::from_millis(40);
    let fut = run_chunked(&s, &r, run.id, vec!["a".into()], o, |_c, _l| async {
        tokio::time::sleep(Duration::from_secs(30)).await;
        Ok(ChunkOutcome::default())
    });
    let _ = tokio::time::timeout(Duration::from_millis(300), fut).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(acquire(&s, &r, run.id, "x", Duration::from_secs(1))
        .await
        .unwrap()
        .is_some());
}

/// Delegates to MemoryStorage with one injected fault.
enum Fault {
    /// A newer holder bumps the fence right after the run is loaded.
    Usurp,
    /// Every checkpoint write fails with a storage error.
    Checkpoint,
}
struct Faulty(MemoryStorage, Fault);
#[async_trait::async_trait]
impl Storage for Faulty {
    async fn create_run(
        &self,
        k: opsagent_core::run::RunKey,
    ) -> opsagent_ledger::Result<opsagent_ledger::CreateRunOutcome> {
        self.0.create_run(k).await
    }
    async fn load_run(&self, id: uuid::Uuid) -> opsagent_ledger::Result<opsagent_ledger::RunRow> {
        let row = self.0.load_run(id).await?;
        if let Fault::Usurp = self.1 {
            self.0.bump_fence(id).await?;
        }
        Ok(row)
    }
    async fn bump_fence(&self, id: uuid::Uuid) -> opsagent_ledger::Result<u64> {
        self.0.bump_fence(id).await
    }
    async fn write_checkpoint(
        &self,
        id: uuid::Uuid,
        f: u64,
        cp: &opsagent_ledger::Checkpoint,
    ) -> opsagent_ledger::Result<()> {
        if let Fault::Checkpoint = self.1 {
            return Err(opsagent_ledger::LedgerError::Storage("disk full".into()));
        }
        self.0.write_checkpoint(id, f, cp).await
    }
    async fn set_status(
        &self,
        id: uuid::Uuid,
        f: u64,
        s: RunStatus,
        r: Option<String>,
    ) -> opsagent_ledger::Result<()> {
        self.0.set_status(id, f, s, r).await
    }
    async fn skip_run(&self, id: uuid::Uuid, r: &str) -> opsagent_ledger::Result<bool> {
        self.0.skip_run(id, r).await
    }
    async fn effect_begin(
        &self,
        id: uuid::Uuid,
        k: &str,
    ) -> opsagent_ledger::Result<opsagent_ledger::EffectState> {
        self.0.effect_begin(id, k).await
    }
    async fn effect_done(
        &self,
        id: uuid::Uuid,
        k: &str,
        r: Option<String>,
    ) -> opsagent_ledger::Result<()> {
        self.0.effect_done(id, k, r).await
    }
    async fn mark_enqueue_pending(
        &self,
        id: uuid::Uuid,
        at: chrono::DateTime<chrono::Utc>,
    ) -> opsagent_ledger::Result<()> {
        self.0.mark_enqueue_pending(id, at).await
    }
    async fn clear_enqueue_marker(
        &self,
        id: uuid::Uuid,
        at: chrono::DateTime<chrono::Utc>,
    ) -> opsagent_ledger::Result<bool> {
        self.0.clear_enqueue_marker(id, at).await
    }
    async fn schedule_retry(
        &self,
        id: uuid::Uuid,
        a: u32,
        n: chrono::DateTime<chrono::Utc>,
    ) -> opsagent_ledger::Result<()> {
        self.0.schedule_retry(id, a, n).await
    }
}

#[tokio::test]
async fn stale_fence_on_initial_running_returns_partial() {
    let (r, s) = (
        common::redis(),
        Faulty(MemoryStorage::default(), Fault::Usurp),
    );
    let run = s.create_run(common::key()).await.unwrap().run;
    let ran = AtomicU32::new(0);
    let st = run_chunked(
        &s,
        &r,
        run.id,
        vec!["a".into()],
        opts("w"),
        |_c, _l| async {
            ran.fetch_add(1, SeqCst);
            Ok(ChunkOutcome::default())
        },
    )
    .await;
    assert_eq!(st.unwrap(), RunStatus::Partial);
    assert_eq!(ran.load(SeqCst), 0);
    let row = s.0.load_run(run.id).await.unwrap();
    assert_eq!(row.status, RunStatus::Queued);
    assert!(row.checkpoint.chunks_done.is_empty());
}

#[tokio::test]
async fn partial_reason_in_stats_ends_partial_even_after_resume() {
    let (r, s) = (common::redis(), MemoryStorage::default());
    let run = s.create_run(common::key()).await.unwrap().run;
    let chunks: Vec<String> = vec!["a".into(), "b".into()];
    let runs = kill_after_each_checkpoint(|kill| {
        let (r, s, chunks) = (&r, &s, chunks.clone());
        async move {
            let mut o = opts("w");
            o.after_checkpoint = Some(kill);
            run_chunked(s, r, run.id, chunks, o, |c, _l| async move {
                let stats = if c == "a" {
                    json!({ "partial_reason": "partial_inventory" })
                } else {
                    json!({})
                };
                Ok(ChunkOutcome {
                    stats,
                    ..Default::default()
                })
            })
            .await
        }
    })
    .await
    .unwrap();
    assert_eq!(runs, 3);
    let row = s.load_run(run.id).await.unwrap();
    assert_eq!(row.status, RunStatus::Partial);
    assert_eq!(row.partial_reason.as_deref(), Some("partial_inventory"));
}

#[tokio::test]
async fn failing_chunk_ends_the_run_failed_or_queued_for_retry() {
    use opsagent_ledger::LedgerError;
    let r = common::redis();
    for (retry, want, attempts) in [(false, RunStatus::Failed, 0), (true, RunStatus::Queued, 1)] {
        let s = MemoryStorage::default();
        let run = s.create_run(common::key()).await.unwrap().run;
        let chunks: Vec<String> = vec!["a".into(), "b".into()];
        let st = run_chunked(&s, &r, run.id, chunks, opts("w"), |c, _l| async move {
            if c == "b" {
                return Err(LedgerError::Job {
                    code: "boom".into(),
                    retry,
                });
            }
            Ok(ChunkOutcome::default())
        })
        .await
        .unwrap();
        assert_eq!(st, want);
        let row = s.load_run(run.id).await.unwrap();
        assert_eq!((row.status, row.attempts), (want, attempts));
        if !retry {
            assert_eq!(row.partial_reason.as_deref(), Some("boom"));
        }
        // The finished chunk stays checkpointed for the retry.
        assert!(row.checkpoint.chunks_done.contains("a"));
    }
}

#[tokio::test]
async fn storage_error_on_checkpoint_ends_the_run_failed() {
    let (r, s) = (
        common::redis(),
        Faulty(MemoryStorage::default(), Fault::Checkpoint),
    );
    let run = s.create_run(common::key()).await.unwrap().run;
    let st = run_chunked(
        &s,
        &r,
        run.id,
        vec!["a".into()],
        opts("w"),
        |_c, _l| async { Ok(ChunkOutcome::default()) },
    )
    .await
    .unwrap();
    assert_eq!(st, RunStatus::Failed);
    let row = s.0.load_run(run.id).await.unwrap();
    assert_eq!(row.status, RunStatus::Failed);
    assert_eq!(row.partial_reason.as_deref(), Some("storage_error"));
}
