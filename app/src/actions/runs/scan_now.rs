//! Operator scan: creates a `full_scan` run for a connection named by id and runs it inline.
use std::sync::Arc;

use opsagent_core::{
    repo::Clock,
    run::{RunKey, RunStatus},
};
use opsagent_ledger::RunChunkedOptions;
use uuid::Uuid;

use super::{full_scan::JOB, FullScan};
use crate::{
    actions::uow::UnitOfWork,
    error::{AppError, AppResult},
};

pub struct ScanNow {
    uow: Arc<dyn UnitOfWork>,
    full_scan: FullScan,
    clock: Arc<dyn Clock>,
}

impl ScanNow {
    pub fn new(uow: Arc<dyn UnitOfWork>, full_scan: FullScan, clock: Arc<dyn Clock>) -> Self {
        Self {
            uow,
            full_scan,
            clock,
        }
    }

    /// `NotFound` for an unknown connection; otherwise the scan's final status.
    pub async fn run(&self, connection_id: Uuid) -> AppResult<RunStatus> {
        // tenancy: operator task; the connection id names its organisation.
        let c = self.uow.connections().by_id_unscoped(connection_id).await?;
        let c = c.ok_or(AppError::NotFound)?;
        let key = RunKey {
            organisation_id: Some(c.organisation_id),
            connection_id: Some(c.id),
            job_type: JOB.as_str().into(),
            scheduled_at: self.clock.now(),
        };
        let run = self.uow.ledger().create_run(key).await?.run;
        let status = self
            .full_scan
            .run(run.id, RunChunkedOptions::default())
            .await?;
        tracing::info!(run_id = %run.id, status = ?status, "scan_now finished");
        Ok(status)
    }
}

#[cfg(test)]
mod tests {
    use opsagent_connectors::{aws::AwsOutbound, Registry};
    use opsagent_core::repo::SystemClock;
    use opsagent_secrets::EnvKek;

    use super::*;
    use crate::adapters::memory::MemStore;

    #[tokio::test]
    async fn unknown_connection_is_not_found() {
        let uow: Arc<dyn UnitOfWork> = Arc::new(MemStore::default());
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        // Never dialled: an unknown id ends before any run or lease exists.
        let redis = opsagent_ledger::redis::Client::open("redis://localhost:1").unwrap();
        let kek = Arc::new(EnvKek::new([7; 32], 1, None));
        let connectors = Arc::new(Registry::new(AwsOutbound::default(), true));
        let full_scan = FullScan::new(uow.clone(), redis, kek, connectors, clock.clone());
        let err = ScanNow::new(uow, full_scan, clock)
            .run(Uuid::new_v4())
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::NotFound), "{err:?}");
    }
}
