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
    let run = s.create_run(common::key()).await.unwrap();
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
}

#[tokio::test]
async fn lease_lost_returns_partial() {
    let (r, s) = (common::redis(), MemoryStorage::default());
    let run = s.create_run(common::key()).await.unwrap();
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
                Ok(ChunkOutcome { stats: json!({}) })
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
    let run = s.create_run(common::key()).await.unwrap();
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
            Ok(ChunkOutcome { stats: json!({}) })
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
    let run = s.create_run(common::key()).await.unwrap();
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
                Ok(ChunkOutcome { stats: json!({}) })
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
    let run = s.create_run(common::key()).await.unwrap();
    let mut o = opts("w");
    o.lease_ttl = Duration::from_millis(200);
    o.heartbeat_every = Duration::from_millis(40);
    let fut = run_chunked(&s, &r, run.id, vec!["a".into()], o, |_c, _l| async {
        tokio::time::sleep(Duration::from_secs(30)).await;
        Ok(ChunkOutcome { stats: json!({}) })
    });
    let _ = tokio::time::timeout(Duration::from_millis(300), fut).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(acquire(&s, &r, run.id, "x", Duration::from_secs(1))
        .await
        .unwrap()
        .is_some());
}
