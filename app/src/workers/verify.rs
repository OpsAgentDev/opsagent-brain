//! `verify` job: hands the run to `VerifyConnection` (PRD 7.2).
use async_trait::async_trait;
use loco_rs::{app::AppContext, bgworker::BackgroundWorker, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use opsagent_ledger::JobKind;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyArgs {
    pub run_id: Uuid,
}

pub struct VerifyWorker {
    ctx: AppContext,
}

#[async_trait]
impl BackgroundWorker<VerifyArgs> for VerifyWorker {
    fn build(ctx: &AppContext) -> Self {
        Self { ctx: ctx.clone() }
    }

    async fn perform(&self, args: VerifyArgs) -> Result<()> {
        let actions = crate::app::actions(&self.ctx)?;
        super::perform(&actions, JobKind::Verify, args.run_id).await
    }
}
