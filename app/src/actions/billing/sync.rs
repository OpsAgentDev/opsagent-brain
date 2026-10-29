//! `billing_sync` (billing.md, Build decisions 3 and 13; PRD 7.9). Stripe bills each period
//! in advance, so an organisation's run sets Stripe's quantity to its live accounts, at least
//! one, at once: down without proration (no refund; the next renewal bills less), up without
//! proration while within the period's `paid_quantity` (a reconnect is not charged twice),
//! and above it with proration. The global run is the nightly pass (`nightly`), which also
//! reconciles each organisation this way.
use std::sync::Arc;

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
/// `tx`, when the organisation is subscribed. Called where the live connections may change.
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
                None => self.nightly(run.id, now).await?,
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
        if !self.settings.stripe_configured {
            return Ok(json!({ "skipped": "stripe_unconfigured" }));
        }
        self.sync_quantity(run.id, org).await
    }

    /// Brings Stripe's quantity to the target under run `run_id`'s ledger: each write has its
    /// own effect key (`billing:quantity:<org>:<quantity>:<proration>`) and Idempotency-Key, and
    /// records the quantity (and `paid_quantity`) it set.
    pub(super) async fn sync_quantity(&self, run_id: Uuid, org: Uuid) -> LResult<Value> {
        let b = self.uow.billing().billing(org).await.map_err(lerr)?;
        let Some(sub) = b.subscription.filter(|s| s.status.is_subscribed()) else {
            return Ok(json!({ "skipped": "not_subscribed" }));
        };
        let live = self.uow.billing().billable_accounts(org, None).await;
        let target = i32::try_from(live.map_err(lerr)?.len().max(1)).unwrap_or(i32::MAX);
        let (current, paid) = (sub.quantity, b.paid_quantity.unwrap_or(sub.quantity));
        if target == current {
            return Ok(json!({ "quantity": current, "changed": false }));
        }
        let id = sub.subscription_id.as_str();
        if target <= paid {
            self.write(run_id, org, id, (target, paid), false).await?;
            return Ok(json!({ "quantity": target, "prorate": false, "changed": true }));
        }
        // Above what this period paid for: back to it free, then prorate only the rest.
        if current < paid {
            self.write(run_id, org, id, (paid, paid), false).await?;
        }
        self.write(run_id, org, id, (target, target), true).await?;
        Ok(json!({ "quantity": target, "prorate": true, "changed": true }))
    }

    /// One quantity write at Stripe, then the stored `(quantity, paid)`.
    async fn write(
        &self,
        run_id: Uuid,
        org: Uuid,
        subscription_id: &str,
        (quantity, paid): (i32, i32),
        prorate: bool,
    ) -> LResult<()> {
        let proration = if prorate { "create_prorations" } else { "none" };
        let key = format!("billing:quantity:{org}:{quantity}:{proration}");
        let idem = format!("{run_id}:{key}");
        let provider = &self.provider;
        with_effect(self.uow.ledger(), run_id, &key, true, || async {
            match provider
                .set_quantity(subscription_id, quantity, prorate, &idem)
                .await
            {
                Ok(()) => {}
                Err(BillingError::NotFound) => {
                    tracing::warn!(error_code = "not_found", "stripe subscription gone");
                    return Ok(None);
                }
                Err(BillingError::Other(code)) => {
                    tracing::warn!(error_code = %code, "stripe quantity update failed");
                    return Err(LedgerError::Job { code, retry: true });
                }
            }
            let repo = self.uow.billing();
            repo.record_quantity(org, quantity, paid)
                .await
                .map_err(lerr)?;
            Ok(None)
        })
        .await?;
        Ok(())
    }
}
