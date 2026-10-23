pub mod common;
pub mod full_scan;
pub mod verify;

use std::time::Duration;

use async_trait::async_trait;
use loco_rs::{app::AppContext, bgworker::BackgroundWorker, Result};
use opsagent_ledger::{JobKind, LedgerError, RunChunkedOptions};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{actions::deliveries::options, app::actions};
use common::err;

/// The weekly sends more mail per chunk than the briefing, so it holds its lease longer.
const WEEKLY_LEASE_TTL: Duration = Duration::from_secs(120);

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
        let opts = options(JobKind::DeliverBriefing.as_str());
        let a = actions(&self.ctx)?;
        match a.deliveries.deliver_briefing.run(args.run_id, opts).await {
            // Another worker holds or took over the run; it decides the outcome.
            Ok(_) | Err(LedgerError::LeaseHeld | LedgerError::StaleFence) => Ok(()),
            Err(e) => Err(err(e)),
        }
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
        let opts = RunChunkedOptions {
            lease_ttl: WEEKLY_LEASE_TTL,
            ..options(JobKind::DeliverWeekly.as_str())
        };
        let a = actions(&self.ctx)?;
        match a.deliveries.deliver_weekly.run(args.run_id, opts).await {
            Ok(_) | Err(LedgerError::LeaseHeld | LedgerError::StaleFence) => Ok(()),
            Err(e) => Err(err(e)),
        }
    }
}
