use std::sync::Arc;

use async_trait::async_trait;
use opsagent_ledger::JobKind;
use uuid::Uuid;

use super::{settled, JobHandler};
use crate::{
    actions::deliveries::{options, DeliverBriefing},
    error::AppResult,
};

/// `deliver_briefing`: runs the `DeliverBriefing` action for the run.
pub struct DeliverBriefingJob(pub Arc<DeliverBriefing>);

#[async_trait]
impl JobHandler for DeliverBriefingJob {
    fn kind(&self) -> JobKind {
        JobKind::DeliverBriefing
    }

    async fn handle(&self, run_id: Uuid) -> AppResult<()> {
        let opts = options(JobKind::DeliverBriefing.as_str());
        settled(self.0.run(run_id, opts).await)
    }
}
