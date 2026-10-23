use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use opsagent_ledger::{JobKind, RunChunkedOptions};
use uuid::Uuid;

use super::{settled, JobHandler};
use crate::{actions::runs::FullScan, error::AppResult};

const TIME_CAP: Duration = Duration::from_secs(6 * 3600);

/// `full_scan`: runs the `FullScan` action for the run (PRD 7.3, jobs.md).
pub struct FullScanJob(pub Arc<FullScan>);

#[async_trait]
impl JobHandler for FullScanJob {
    fn kind(&self) -> JobKind {
        JobKind::FullScan
    }

    async fn handle(&self, run_id: Uuid) -> AppResult<()> {
        let opts = RunChunkedOptions {
            worker_id: format!("{}-{}", JobKind::FullScan.as_str(), Uuid::new_v4()),
            time_cap: TIME_CAP,
            ..Default::default()
        };
        settled(self.0.run(run_id, opts).await)
    }
}
