//! `retention` (retention.md): the global nightly run. Each step deletes in batches until
//! nothing is left or the run cap is reached; whatever is left waits for the next night.
mod runs;
mod ttl;

use std::{collections::BTreeMap, future::Future, sync::Arc, time::Duration};

use chrono::{DateTime, Utc};
use opsagent_core::{
    repo::{Clock, RepoResult},
    run::RunStatus,
};
use opsagent_ledger::{redis, run_chunked, ChunkOutcome, RunChunkedOptions};
use tokio::time::Instant;
use uuid::Uuid;

use crate::{
    actions::{
        runs::classify::{lerr, LResult},
        uow::UnitOfWork,
    },
    error::AppResult,
};

/// Rows per delete statement, so locks stay short.
pub const RETENTION_BATCH: u64 = 5000;
/// One run's cap.
pub const RUN_CAP: Duration = Duration::from_secs(30 * 60);

/// Rows deleted per step key (a table name for TTL), counts only. `time_capped`: the run
/// stopped at the cap with rows left.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RetentionStats {
    pub counts: BTreeMap<&'static str, u64>,
    pub time_capped: bool,
}

/// Calls `step` until it deletes fewer than `batch` rows, or until `deadline` passes (then
/// sets `time_capped`); returns the rows deleted.
async fn batched<F, Fut>(
    batch: u64,
    deadline: Instant,
    stats: &mut RetentionStats,
    mut step: F,
) -> AppResult<u64>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = RepoResult<u64>>,
{
    let mut total = 0;
    loop {
        if Instant::now() >= deadline {
            stats.time_capped = true;
            return Ok(total);
        }
        let n = step().await?;
        total += n;
        if n < batch {
            return Ok(total);
        }
    }
}

#[derive(Clone)]
pub struct Retention {
    uow: Arc<dyn UnitOfWork>,
    redis: redis::Client,
    clock: Arc<dyn Clock>,
    batch: u64,
}

impl Retention {
    pub fn new(uow: Arc<dyn UnitOfWork>, redis: redis::Client, clock: Arc<dyn Clock>) -> Self {
        Self {
            uow,
            redis,
            clock,
            batch: RETENTION_BATCH,
        }
    }

    /// Rows per delete statement (tests use a small one).
    pub fn with_batch(mut self, batch: u64) -> Self {
        self.batch = batch.max(1);
        self
    }

    /// Every step in order, at `now`, until done or `RUN_CAP`.
    pub async fn run(&self, now: DateTime<Utc>) -> AppResult<RetentionStats> {
        let deadline = Instant::now() + RUN_CAP;
        let mut stats = RetentionStats::default();
        let repo = self.uow.retention();
        ttl::run(repo, now, self.batch, deadline, &mut stats).await?;
        runs::run(repo, now, self.batch, deadline, &mut stats).await?;
        Ok(stats)
    }

    /// Runs (or resumes) retention run `run_id` under its ledger lease; the counts go to
    /// `runs.checkpoint.stats`. A run stopped at the cap ends `partial` (`time_cap`).
    pub async fn run_job(&self, run_id: Uuid, opts: RunChunkedOptions) -> LResult<RunStatus> {
        let storage = self.uow.ledger();
        let run = storage.load_run(run_id).await?;
        if !matches!(run.status, RunStatus::Queued | RunStatus::Running) {
            return Ok(run.status); // duplicate delivery of a finished run
        }
        let chunks = vec!["retention".to_owned()];
        run_chunked(storage, &self.redis, run_id, chunks, opts, |_, _| async {
            let st = self.run(self.clock.now()).await.map_err(lerr)?;
            let mut stats = serde_json::json!(st.counts);
            if st.time_capped {
                stats["partial_reason"] = "time_cap".into();
            }
            tracing::info!(counts = %stats, "retention done");
            Ok(ChunkOutcome {
                stats,
                ..Default::default()
            })
        })
        .await
    }
}
