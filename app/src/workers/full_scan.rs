//! `full_scan` job: runs the `FullScan` action for the run (PRD 7.3, jobs.md).
use std::sync::Arc;

use async_trait::async_trait;
use loco_rs::{app::AppContext, bgworker::BackgroundWorker, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::common::err;
use crate::jobs::{FullScanJob, JobHandler};

pub const JOB: &str = "full_scan";

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
        let job = FullScanJob(Arc::new(actions.runs.full_scan.clone()));
        job.handle(args.run_id).await.map_err(err)
    }
}
