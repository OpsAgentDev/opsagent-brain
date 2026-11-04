use std::sync::Arc;

use async_trait::async_trait;
use opsagent_ledger::JobKind;
use uuid::Uuid;

use super::{settled, JobHandler};
use crate::{
    actions::{deliveries::options, human_reviews::DeliverReviewNotice},
    error::AppResult,
};

/// `deliver_review_notice`: the two mails of a paid human review (human-review.md).
pub struct DeliverReviewNoticeJob(pub Arc<DeliverReviewNotice>);

#[async_trait]
impl JobHandler for DeliverReviewNoticeJob {
    fn kind(&self) -> JobKind {
        JobKind::DeliverReviewNotice
    }

    async fn handle(&self, run_id: Uuid) -> AppResult<()> {
        let opts = options(JobKind::DeliverReviewNotice.as_str());
        settled(self.0.run(run_id, opts).await)
    }
}
