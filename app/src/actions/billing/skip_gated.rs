//! `SkipGatedRun`: a scan or delivery job of a billing-gated organisation ends its run
//! `Skipped` `billing` when a worker picks it up, whatever queued it (the scheduler before the
//! org was gated, a retry, a chunk continuation, a scan's `deliver_alert`).
use std::{sync::Arc, time::Duration};

use opsagent_core::run::RunStatus;
use opsagent_ledger::{lease, redis, LedgerError};
use uuid::Uuid;

use super::BillingGate;
use crate::{actions::uow::UnitOfWork, error::AppResult};

const LEASE_TTL: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct SkipGatedRun {
    uow: Arc<dyn UnitOfWork>,
    redis: redis::Client,
    gate: BillingGate,
}

impl SkipGatedRun {
    pub fn new(uow: Arc<dyn UnitOfWork>, redis: redis::Client, gate: BillingGate) -> Self {
        Self { uow, redis, gate }
    }

    /// `true` when run `run_id` is (now) skipped for billing, or another worker holds it, so
    /// the job has nothing to do; `false` to run it as usual.
    pub async fn run(&self, run_id: Uuid) -> AppResult<bool> {
        if !self.gate.enforced() {
            return Ok(false);
        }
        let storage = self.uow.ledger();
        let run = storage.load_run(run_id).await?;
        let open = matches!(run.status, RunStatus::Queued | RunStatus::Running);
        let Some(org) = run.key.organisation_id.filter(|_| open) else {
            return Ok(false);
        };
        if !self.gate.gated(&*self.uow, org).await? {
            return Ok(false);
        }
        let worker = format!("billing-gate-{}", Uuid::new_v4());
        let lease = match lease::acquire(storage, &self.redis, run_id, &worker, LEASE_TTL).await {
            Ok(Some(l)) => l,
            // The holder's next fenced write decides; this job is done.
            Ok(None) | Err(LedgerError::LeaseHeld) => return Ok(true),
            Err(e) => return Err(e.into()),
        };
        let skipped = storage
            .set_status(
                run_id,
                lease.fence,
                RunStatus::Skipped,
                Some("billing".into()),
            )
            .await;
        lease::release(&self.redis, &lease).await;
        match skipped {
            Ok(()) | Err(LedgerError::StaleFence) => Ok(true),
            Err(e) => Err(e.into()),
        }
    }
}
