use std::sync::Arc;

use async_trait::async_trait;
use opsagent_ledger::JobKind;
use uuid::Uuid;

use super::{settled, JobHandler};
use crate::{
    actions::{deliveries::options, runs::DeliverRevokedNotice},
    error::AppResult,
};

/// `deliver_revoked_notice`, `deliver_claimed_notice` or `deliver_scans_failing_notice` (the
/// `JobKind`): the owners' mail when a connection becomes revoked, when another organisation
/// tried to claim its account, or when its nightly scans keep failing.
pub struct DeliverRevokedNoticeJob(pub Arc<DeliverRevokedNotice>, pub JobKind);

#[async_trait]
impl JobHandler for DeliverRevokedNoticeJob {
    fn kind(&self) -> JobKind {
        self.1
    }

    async fn handle(&self, run_id: Uuid) -> AppResult<()> {
        let opts = options(self.1.as_str());
        settled(self.0.run(run_id, opts).await)
    }
}
