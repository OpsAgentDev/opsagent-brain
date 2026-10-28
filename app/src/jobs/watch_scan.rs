use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use opsagent_ledger::{JobKind, RunChunkedOptions};
use uuid::Uuid;

use super::{settled, JobHandler};
use crate::{actions::runs::FullScan, error::AppResult};

/// A watch scan stops (partial) after this long, so it never runs into the next one.
const TIME_CAP: Duration = Duration::from_secs(120);

/// `watch_scan`: runs the watch profile of `FullScan` for the run (urgent-alerts spec).
pub struct WatchScanJob(pub Arc<FullScan>);

#[async_trait]
impl JobHandler for WatchScanJob {
    fn kind(&self) -> JobKind {
        JobKind::WatchScan
    }

    async fn handle(&self, run_id: Uuid) -> AppResult<()> {
        let opts = RunChunkedOptions {
            worker_id: format!("{}-{}", JobKind::WatchScan.as_str(), Uuid::new_v4()),
            time_cap: TIME_CAP,
            ..Default::default()
        };
        settled(self.0.run(run_id, opts).await)
    }
}
