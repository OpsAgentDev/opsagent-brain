use std::sync::Arc;

use async_trait::async_trait;
use opsagent_ledger::JobKind;
use uuid::Uuid;

use super::{settled, JobHandler};
use crate::{
    actions::{deliveries::options, runs::ContactsExport},
    error::AppResult,
};

/// `contacts_export`: the weekly CSV of organisation owners for the CRM sheet.
pub struct ContactsExportJob(pub Arc<ContactsExport>);

#[async_trait]
impl JobHandler for ContactsExportJob {
    fn kind(&self) -> JobKind {
        JobKind::ContactsExport
    }

    async fn handle(&self, run_id: Uuid) -> AppResult<()> {
        let opts = options(JobKind::ContactsExport.as_str());
        settled(self.0.run(run_id, opts).await)
    }
}
