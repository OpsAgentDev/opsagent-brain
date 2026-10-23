//! `full_scan` job: runs the `FullScan` action for the run (PRD 7.3, jobs.md).
use std::time::Duration;

use async_trait::async_trait;
use loco_rs::{app::AppContext, bgworker::BackgroundWorker, Result};
use opsagent_ledger::{JobKind, RunChunkedOptions};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const JOB: &str = "full_scan";
const TIME_CAP: Duration = Duration::from_secs(6 * 3600);

pub(crate) fn options() -> RunChunkedOptions {
    RunChunkedOptions {
        worker_id: format!("{JOB}-{}", Uuid::new_v4()),
        time_cap: TIME_CAP,
        ..Default::default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullScanArgs {
    pub run_id: Uuid,
}

pub struct FullScanWorker {
    ctx: AppContext,
}

#[async_trait]
impl BackgroundWorker<FullScanArgs> for FullScanWorker {
    fn build(ctx: &AppContext) -> Self {
        Self { ctx: ctx.clone() }
    }

    async fn perform(&self, args: FullScanArgs) -> Result<()> {
        let actions = crate::app::actions(&self.ctx)?;
        super::perform(&actions, JobKind::FullScan, args.run_id).await
    }
}
