//! shortcut: Loco's Redis queue behind the `Queue` port; deleted when the Postgres queue
//! lands (Task 18). The only place that names a Loco worker for enqueueing.
use async_trait::async_trait;
use loco_rs::{app::AppContext, bgworker::BackgroundWorker};
use opsagent_ledger::{JobKind, LedgerError, NewJob, Queue};

use crate::workers::{
    deliver_briefing::{DeliverBriefingArgs, DeliverBriefingWorker},
    deliver_weekly::{DeliverWeeklyArgs, DeliverWeeklyWorker},
    full_scan::{FullScanArgs, FullScanWorker},
    verify::{VerifyArgs, VerifyWorker},
};

pub struct LocoQueue(pub AppContext);

#[async_trait]
impl Queue for LocoQueue {
    /// `run_at` is not passed on: Loco enqueues for now, and every caller's `run_at` is due.
    async fn enqueue(&self, job: NewJob) -> opsagent_ledger::Result<()> {
        let (ctx, run_id) = (&self.0, job.run_id);
        match job.kind {
            JobKind::Verify => VerifyWorker::perform_later(ctx, VerifyArgs { run_id }).await,
            JobKind::FullScan => FullScanWorker::perform_later(ctx, FullScanArgs { run_id }).await,
            JobKind::DeliverBriefing => {
                DeliverBriefingWorker::perform_later(ctx, DeliverBriefingArgs { run_id }).await
            }
            JobKind::DeliverWeekly => {
                DeliverWeeklyWorker::perform_later(ctx, DeliverWeeklyArgs { run_id }).await
            }
        }
        .map(drop)
        .map_err(|e| LedgerError::Storage(e.to_string()))
    }
}
