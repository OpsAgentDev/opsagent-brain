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
