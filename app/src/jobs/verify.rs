use std::sync::Arc;

use async_trait::async_trait;
use opsagent_ledger::JobKind;
use uuid::Uuid;

use super::JobHandler;
use crate::{actions::runs::VerifyConnection, error::AppResult};

/// `verify`: hands the run to `VerifyConnection` (PRD 7.2).
pub struct VerifyJob(pub Arc<VerifyConnection>);

#[async_trait]
impl JobHandler for VerifyJob {
    fn kind(&self) -> JobKind {
        JobKind::Verify
    }

    async fn handle(&self, run_id: Uuid) -> AppResult<()> {
        self.0.run(run_id).await
    }
}
