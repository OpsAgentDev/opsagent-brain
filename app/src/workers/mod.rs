pub mod common;
pub mod full_scan;
pub mod verify;

use std::time::Duration;

use async_trait::async_trait;
use loco_rs::{app::AppContext, bgworker::BackgroundWorker, Result};
use opsagent_ledger::{JobKind, LedgerError, RunChunkedOptions};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    actions::{deliveries::options, Actions},
    app::actions,
};
use common::err;

/// The weekly sends more mail per chunk than the briefing, so it holds its lease longer.
const WEEKLY_LEASE_TTL: Duration = Duration::from_secs(120);

/// One `kind` job for `run_id`, as its worker runs it. The Loco workers and the test queue
/// share it until Task 17's job handlers replace both.
pub async fn perform(a: &Actions, kind: JobKind, run_id: Uuid) -> Result<()> {
    let out = match kind {
        JobKind::Verify => return a.runs.verify_connection.run(run_id).await.map_err(err),
        JobKind::FullScan => a.runs.full_scan.run(run_id, full_scan::options()).await,
        JobKind::DeliverBriefing => {
            let opts = options(kind.as_str());
            a.deliveries.deliver_briefing.run(run_id, opts).await
        }
        JobKind::DeliverWeekly => {
            let opts = RunChunkedOptions {
                lease_ttl: WEEKLY_LEASE_TTL,
                ..options(kind.as_str())
            };
            a.deliveries.deliver_weekly.run(run_id, opts).await
        }
    };
    match out {
        // Another worker holds or took over the run; it decides the outcome.
        Ok(_) | Err(LedgerError::LeaseHeld | LedgerError::StaleFence) => Ok(()),
        Err(e) => Err(err(e)),
    }
}

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
        perform(&*actions(&self.ctx)?, JobKind::DeliverBriefing, args.run_id).await
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
        perform(&*actions(&self.ctx)?, JobKind::DeliverWeekly, args.run_id).await
    }
}
