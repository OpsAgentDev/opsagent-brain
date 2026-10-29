//! Runs step: old operational runs and their dependents (retention.md, goal 3); which runs
//! qualify is the repository's prunable-run rule.
use chrono::{DateTime, Duration, Utc};
use opsagent_core::retention::RetentionRepo;
use tokio::time::Instant;

use super::{batched, RetentionStats};
use crate::error::AppResult;

/// Runs scheduled more than this long ago may be pruned.
const PRUNE_AFTER_DAYS: i64 = 14;

/// Prunes runs in batches of `batch`, recording the count as `runs`; stops with
/// `time_capped` at `deadline`.
pub(super) async fn run(
    repo: &dyn RetentionRepo,
    now: DateTime<Utc>,
    batch: u64,
    deadline: Instant,
    stats: &mut RetentionStats,
) -> AppResult<()> {
    let older_than = now - Duration::days(PRUNE_AFTER_DAYS);
    let n = batched(batch, deadline, stats, || {
        repo.prune_runs(older_than, batch)
    })
    .await?;
    stats.counts.insert("runs", n);
    Ok(())
}

#[cfg(test)]
mod tests {
    use opsagent_core::run::{RunKey, RunStatus};
    use uuid::Uuid;

    use super::*;
    use crate::adapters::memory::MemStore;

    async fn watch_run(store: &MemStore, at: DateTime<Utc>) {
        let key = RunKey {
            organisation_id: Some(Uuid::now_v7()),
            connection_id: Some(Uuid::now_v7()),
            job_type: "watch_scan".into(),
            scheduled_at: at,
        };
        store.seed_run(key, RunStatus::Done).await;
    }

    #[tokio::test]
    async fn runs_loops_batches_and_keeps_young_runs() {
        let store = MemStore::default();
        let now = Utc::now();
        for d in [15, 16, 17, 20, 13] {
            watch_run(&store, now - Duration::days(d)).await;
        }
        let mut stats = RetentionStats::default();
        let far = Instant::now() + std::time::Duration::from_secs(60);
        run(&store, now, 2, far, &mut stats).await.unwrap();
        assert_eq!(stats.counts["runs"], 4);
        assert!(!stats.time_capped);
        assert_eq!(store.prune_runs(now, 100).await.unwrap(), 1); // the 13-day one
    }

    #[tokio::test]
    async fn runs_stops_at_the_deadline() {
        let store = MemStore::default();
        let now = Utc::now();
        watch_run(&store, now - Duration::days(20)).await;
        let mut stats = RetentionStats::default();
        run(&store, now, 2, Instant::now(), &mut stats)
            .await
            .unwrap();
        assert!(stats.time_capped);
        assert_eq!(stats.counts["runs"], 0);
        assert_eq!(store.prune_runs(now, 100).await.unwrap(), 1);
    }
}
