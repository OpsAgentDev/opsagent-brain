use std::sync::Arc;

use async_trait::async_trait;
use opsagent_ledger::{JobKind, RunChunkedOptions};
use uuid::Uuid;

use super::{settled, JobHandler};
use crate::{
    actions::{
        deliveries::options,
        retention::{Retention, RUN_CAP},
    },
    error::AppResult,
};

/// `retention`: the global nightly run (retention.md).
pub struct RetentionJob(pub Arc<Retention>);

#[async_trait]
impl JobHandler for RetentionJob {
    fn kind(&self) -> JobKind {
        JobKind::Retention
    }

    async fn handle(&self, run_id: Uuid) -> AppResult<()> {
        let opts = RunChunkedOptions {
            time_cap: RUN_CAP,
            ..options(JobKind::Retention.as_str())
        };
        settled(self.0.run_job(run_id, opts).await)
    }
}
