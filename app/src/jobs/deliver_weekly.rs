use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use opsagent_ledger::{JobKind, RunChunkedOptions};
use uuid::Uuid;

use super::{settled, JobHandler};
use crate::{
    actions::deliveries::{options, DeliverWeekly},
    error::AppResult,
};

/// The weekly sends more mail per chunk than the briefing, so it holds its lease longer.
const LEASE_TTL: Duration = Duration::from_secs(120);

/// `deliver_weekly`: runs the `DeliverWeekly` action for the run.
pub struct DeliverWeeklyJob(pub Arc<DeliverWeekly>);

#[async_trait]
impl JobHandler for DeliverWeeklyJob {
    fn kind(&self) -> JobKind {
        JobKind::DeliverWeekly
    }

    async fn handle(&self, run_id: Uuid) -> AppResult<()> {
        let opts = RunChunkedOptions {
            lease_ttl: LEASE_TTL,
            ..options(JobKind::DeliverWeekly.as_str())
        };
        settled(self.0.run(run_id, opts).await)
    }
}
