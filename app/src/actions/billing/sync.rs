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
    /// records the quantity (and `paid_quantity`) it set. All of it runs in one transaction
    /// holding the organisation's quantity lock, so concurrent syncs reach Stripe and storage
    /// in the same order, and each reads the state the previous one committed. A failure rolls
    /// back the records with their effects; the retry replays the same Idempotency-Keys.
    pub(super) async fn sync_quantity(&self, run_id: Uuid, org: Uuid) -> LResult<Value> {
        let tx = self.uow.begin().await.map_err(lerr)?;
        tx.billing().lock_quantity(org).await.map_err(lerr)?;
        let out = self.sync_locked(&*tx, run_id, org).await?;
        tx.commit().await.map_err(lerr)?;
        Ok(out)
    }

    async fn sync_locked(&self, tx: &dyn Tx, run_id: Uuid, org: Uuid) -> LResult<Value> {
        let b = tx.billing().billing(org).await.map_err(lerr)?;
        let Some(sub) = b.subscription.filter(|s| s.status.is_subscribed()) else {
            return Ok(json!({ "skipped": "not_subscribed" }));
        };
        let live = tx.billing().billable_accounts(org, None).await;
        let target = i32::try_from(live.map_err(lerr)?.len().max(1)).unwrap_or(i32::MAX);
        let current = sub.quantity;
        // Renewed but the rollover not yet applied: the new period has paid only `current`.
        let renewed = sub
            .current_period_end
            .is_some_and(|e| e <= self.clock.now());
        let paid = match renewed {
            true => current,
            false => b.paid_quantity.unwrap_or(current),
        };
        if target == current {
            return Ok(json!({ "quantity": current, "changed": false }));
        }
        let w = Write {
            tx,
            run_id,
            org,
            subscription_id: sub.subscription_id.as_str(),
        };
        if target <= paid {
            self.write(&w, (target, paid), false).await?;
            return Ok(json!({ "quantity": target, "prorate": false, "changed": true }));
        }
        // Above what this period paid for: back to it free, then prorate only the rest.
        if current < paid {
            self.write(&w, (paid, paid), false).await?;
        }
        self.write(&w, (target, target), true).await?;
        Ok(json!({ "quantity": target, "prorate": true, "changed": true }))
    }

    /// One quantity write at Stripe, then the stored `(quantity, paid)`, on `w.tx`.
    async fn write(
        &self,
        w: &Write<'_>,
        (quantity, paid): (i32, i32),
        prorate: bool,
    ) -> LResult<()> {
        let proration = if prorate { "create_prorations" } else { "none" };
        let key = format!("billing:quantity:{}:{quantity}:{proration}", w.org);
        let idem = format!("{}:{key}", w.run_id);
        let provider = &self.provider;
        with_effect(w.tx.ledger(), w.run_id, &key, true, || async {
            match provider
                .set_quantity(w.subscription_id, quantity, prorate, &idem)
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
            let repo = w.tx.billing();
            repo.record_quantity(w.org, quantity, paid)
                .await
                .map_err(lerr)?;
            Ok(None)
        })
        .await?;
        Ok(())
    }
}

/// Where a quantity write goes: the locked transaction, the run's ledger, the subscription.
struct Write<'a> {
    tx: &'a dyn Tx,
    run_id: Uuid,
    org: Uuid,
    subscription_id: &'a str,
}
