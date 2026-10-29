//! `billing_sync` (billing.md, Build decisions 3 and 13). An organisation's run sets Stripe's
//! quantity to the billable count: up at once with proration, down only in the run the period
//! rollover enqueued (keyed at the new `current_period_start`), without proration. The global
//! run is the nightly pass (`nightly`).
use std::{cmp::Ordering, sync::Arc};

use chrono::{DateTime, Utc};
use opsagent_core::{
    billing::{BillingError, BillingProvider},
    repo::Clock,
    run::{RunKey, RunStatus},
};
use opsagent_ledger::{
    effects::with_effect, redis, run_chunked, ChunkOutcome, JobKind, LedgerError, NewJob,
    RunChunkedOptions, RunRow,
};
use serde_json::{json, Value};
use uuid::Uuid;

use super::BillingSettings;
use crate::{
    actions::{
        recipients::MailGuard,
        runs::classify::{lerr, LResult},
        uow::{Tx, UnitOfWork},
    },
    error::AppResult,
    mailers::Mailer,
};

/// Creates (once per key) and enqueues the organisation's `billing_sync` run at `at`, on
/// `tx`, when the organisation is subscribed. Called where the billable count may change, and
/// with the new period start on a rollover.
pub async fn enqueue_sync(tx: &dyn Tx, organisation_id: Uuid, at: DateTime<Utc>) -> AppResult<()> {
    if !tx
        .billing()
        .billing(organisation_id)
        .await?
        .status
        .is_subscribed()
    {
        return Ok(());
    }
    let key = RunKey {
        organisation_id: Some(organisation_id),
        connection_id: None,
        job_type: JobKind::BillingSync.as_str().into(),
        scheduled_at: at,
    };
    let out = tx.ledger().create_run(key).await?;
    if out.created {
        let job = NewJob {
            kind: JobKind::BillingSync,
            run_id: out.run.id,
            run_at: at,
        };
        tx.queue().enqueue(job).await?;
    }
    Ok(())
}

#[derive(Clone)]
pub struct BillingSync {
    pub(super) uow: Arc<dyn UnitOfWork>,
    redis: redis::Client,
    provider: Arc<dyn BillingProvider>,
    pub(super) mailer: Arc<dyn Mailer>,
    pub(super) guard: Arc<MailGuard>,
    clock: Arc<dyn Clock>,
    pub(super) settings: BillingSettings,
}

impl BillingSync {
    pub fn new(
        uow: Arc<dyn UnitOfWork>,
        redis: redis::Client,
        provider: Arc<dyn BillingProvider>,
        (mailer, guard): (Arc<dyn Mailer>, Arc<MailGuard>),
        clock: Arc<dyn Clock>,
        settings: BillingSettings,
    ) -> Self {
        Self {
            uow,
            redis,
            provider,
            mailer,
            guard,
            clock,
            settings,
        }
    }

    /// Runs (or resumes) `billing_sync` run `run_id` under its ledger lease.
    pub async fn run_job(&self, run_id: Uuid, opts: RunChunkedOptions) -> LResult<RunStatus> {
        let storage = self.uow.ledger();
        let run = storage.load_run(run_id).await?;
        if !matches!(run.status, RunStatus::Queued | RunStatus::Running) {
            return Ok(run.status); // duplicate delivery of a finished run
        }
        let chunks = vec!["billing_sync".to_owned()];
        run_chunked(storage, &self.redis, run_id, chunks, opts, |_, _| async {
            let now = self.clock.now();
            let stats = match run.key.organisation_id {
                Some(org) => self.sync_org(&run, org).await?,
                None => self.nightly(now).await?,
            };
            Ok(ChunkOutcome {
                stats,
                ..Default::default()
            })
        })
        .await
    }

    /// Sets the quantity for organisation run `run`; its stats say what was set.
    async fn sync_org(&self, run: &RunRow, org: Uuid) -> LResult<Value> {
        let skip = |why: &str| Ok(json!({ "skipped": why }));
        if !self.settings.stripe_configured {
            return skip("stripe_unconfigured");
        }
        let b = self.uow.billing().billing(org).await.map_err(lerr)?;
        let sub = b.subscription.filter(|_| b.status.is_subscribed());
        let Some((sub, start)) = sub.and_then(|s| s.current_period_start.map(|p| (s, p))) else {
            return skip("not_subscribed");
        };
        let rollover = run.key.scheduled_at == start;
        if rollover {
            // A connection revoked through the period that just ended is not billed for this
            // one, even before the nightly pass gets to it.
            self.end_revoked(org, &sub, self.clock.now()).await?;
        }
        let count = self.uow.billing().billable_count(org, start).await;
        let target = i32::try_from(count.map_err(lerr)?.max(1)).unwrap_or(i32::MAX);
        let prorate = match target.cmp(&sub.quantity) {
            Ordering::Greater => true,
            Ordering::Less if rollover => false,
            _ => return Ok(json!({ "quantity": sub.quantity, "changed": false })),
        };
        let key = format!("billing:quantity:{target}");
        let idem = format!("{}:{key}", run.id);
        let (provider, id) = (&self.provider, sub.subscription_id.as_str());
        with_effect(self.uow.ledger(), run.id, &key, true, || async {
            match provider.set_quantity(id, target, prorate, &idem).await {
                Ok(()) => Ok(None),
                Err(BillingError::NotFound) => {
                    tracing::warn!(error_code = "not_found", "stripe subscription gone");
                    Ok(None)
                }
                Err(BillingError::Other(code)) => {
                    tracing::warn!(error_code = %code, "stripe quantity update failed");
                    Err(LedgerError::Job { code, retry: true })
                }
            }
        })
        .await?;
        Ok(json!({ "quantity": target, "prorate": prorate, "changed": true }))
    }
}
