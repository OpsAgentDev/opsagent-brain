use std::sync::Arc;

use async_trait::async_trait;
use opsagent_ledger::JobKind;
use uuid::Uuid;

use super::{settled, JobHandler};
use crate::{
    actions::deliveries::{options, DeliverAlert},
    error::AppResult,
};

/// `deliver_alert`: runs the `DeliverAlert` action for the run.
pub struct DeliverAlertJob(pub Arc<DeliverAlert>);

#[async_trait]
impl JobHandler for DeliverAlertJob {
    fn kind(&self) -> JobKind {
        JobKind::DeliverAlert
    }

    async fn handle(&self, run_id: Uuid) -> AppResult<()> {
        let opts = options(JobKind::DeliverAlert.as_str());
        settled(self.0.run(run_id, opts).await)
    }
}
