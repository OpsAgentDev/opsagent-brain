//! Job handlers and the `WorkerRunner` that drains the `jobs` table (app-shell.md, jobs).
//! A handler hands its run to one action; the run's ledger decides retries and resume.
mod deliver_briefing;
mod deliver_weekly;
mod full_scan;
mod runner;
mod verify;

use async_trait::async_trait;
use opsagent_core::run::RunStatus;
use opsagent_ledger::{JobKind, LedgerError};
use uuid::Uuid;

use crate::error::AppResult;

pub use deliver_briefing::DeliverBriefingJob;
pub use deliver_weekly::DeliverWeeklyJob;
pub use full_scan::FullScanJob;
pub use runner::WorkerRunner;
pub use verify::VerifyJob;

#[async_trait]
pub trait JobHandler: Send + Sync {
    fn kind(&self) -> JobKind;
    async fn handle(&self, run_id: Uuid) -> AppResult<()>;
}

/// A chunked run's result as a job's: another worker holding or having taken over the run
/// decides its outcome, so this job is done.
fn settled(out: Result<RunStatus, LedgerError>) -> AppResult<()> {
    match out {
        Ok(_) | Err(LedgerError::LeaseHeld | LedgerError::StaleFence) => Ok(()),
        Err(e) => Err(e.into()),
    }
}
