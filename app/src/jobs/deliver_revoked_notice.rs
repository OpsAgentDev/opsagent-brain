use std::sync::Arc;

use async_trait::async_trait;
use opsagent_ledger::JobKind;
use uuid::Uuid;

use super::{settled, JobHandler};
use crate::{
    actions::{deliveries::options, runs::DeliverRevokedNotice},
    error::AppResult,
};

/// `deliver_revoked_notice`: the owners' mail when a connection becomes revoked.
pub struct DeliverRevokedNoticeJob(pub Arc<DeliverRevokedNotice>);

#[async_trait]
impl JobHandler for DeliverRevokedNoticeJob {
    fn kind(&self) -> JobKind {
        JobKind::DeliverRevokedNotice
    }

    async fn handle(&self, run_id: Uuid) -> AppResult<()> {
        let opts = options(JobKind::DeliverRevokedNotice.as_str());
        settled(self.0.run(run_id, opts).await)
    }
}
