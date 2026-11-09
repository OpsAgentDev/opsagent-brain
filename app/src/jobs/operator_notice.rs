use std::sync::Arc;

use async_trait::async_trait;
use opsagent_ledger::JobKind;
use uuid::Uuid;

use super::{settled, JobHandler};
use crate::{
    actions::{deliveries::options, runs::OperatorNotice},
    error::AppResult,
};

/// `operator_notice`: the nightly mail to the contact address.
pub struct OperatorNoticeJob(pub Arc<OperatorNotice>);

#[async_trait]
impl JobHandler for OperatorNoticeJob {
    fn kind(&self) -> JobKind {
        JobKind::OperatorNotice
    }

    async fn handle(&self, run_id: Uuid) -> AppResult<()> {
        let opts = options(JobKind::OperatorNotice.as_str());
        settled(self.0.run(run_id, opts).await)
    }
}
