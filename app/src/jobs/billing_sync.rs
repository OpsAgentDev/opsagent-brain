use std::sync::Arc;

use async_trait::async_trait;
use opsagent_ledger::JobKind;
use uuid::Uuid;

use super::{settled, JobHandler};
use crate::{
    actions::{billing::BillingSync, deliveries::options},
    error::AppResult,
};

/// `billing_sync`: an organisation's quantity sync, or the global nightly pass (billing.md).
pub struct BillingSyncJob(pub Arc<BillingSync>);

#[async_trait]
impl JobHandler for BillingSyncJob {
    fn kind(&self) -> JobKind {
        JobKind::BillingSync
    }

    async fn handle(&self, run_id: Uuid) -> AppResult<()> {
        let opts = options(JobKind::BillingSync.as_str());
        settled(self.0.run_job(run_id, opts).await)
    }
}
