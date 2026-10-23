pub mod common;
pub mod full_scan;
pub mod verify;

use std::sync::Arc;

use async_trait::async_trait;
use loco_rs::{app::AppContext, bgworker::BackgroundWorker, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    app::actions,
    jobs::{DeliverBriefingJob, DeliverWeeklyJob, JobHandler},
};
use common::err;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliverBriefingArgs {
    pub run_id: Uuid,
}

/// `deliver_briefing` job: runs the `DeliverBriefing` action for the run.
pub struct DeliverBriefingWorker {
    ctx: AppContext,
}

#[async_trait]
impl BackgroundWorker<DeliverBriefingArgs> for DeliverBriefingWorker {
    fn build(ctx: &AppContext) -> Self {
        Self { ctx: ctx.clone() }
    }

    async fn perform(&self, args: DeliverBriefingArgs) -> Result<()> {
        let a = &actions(&self.ctx)?.deliveries;
        let job = DeliverBriefingJob(Arc::new(a.deliver_briefing.clone()));
        job.handle(args.run_id).await.map_err(err)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliverWeeklyArgs {
    pub run_id: Uuid,
}

/// `deliver_weekly` job: runs the `DeliverWeekly` action for the run.
pub struct DeliverWeeklyWorker {
    ctx: AppContext,
}

#[async_trait]
impl BackgroundWorker<DeliverWeeklyArgs> for DeliverWeeklyWorker {
    fn build(ctx: &AppContext) -> Self {
        Self { ctx: ctx.clone() }
    }

    async fn perform(&self, args: DeliverWeeklyArgs) -> Result<()> {
        let a = &actions(&self.ctx)?.deliveries;
        let job = DeliverWeeklyJob(Arc::new(a.deliver_weekly.clone()));
        job.handle(args.run_id).await.map_err(err)
    }
}
