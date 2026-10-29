use std::sync::Arc;

use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use opsagent_core::{
    billing::{BillingStatus as B, SubscriptionState},
    repo::{Clock, RepoError},
};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use super::{enqueue_sync, unavailable, BillingSettings};
use crate::{
    actions::uow::{Tx, UnitOfWork},
    adapters::stripe::verify_stripe_signature,
    error::{AppError, AppResult},
};

const HANDLED: [&str; 6] = [
    "checkout.session.completed",
    "customer.subscription.created",
    "customer.subscription.updated",
    "customer.subscription.deleted",
    "invoice.payment_failed",
    "invoice.payment_succeeded",
];

#[derive(Deserialize)]
struct Event {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    created: i64,
    data: EventData,
}

#[derive(Deserialize)]
struct EventData {
    object: Value,
}

fn bad_request(code: &'static str, detail: &str) -> AppError {
    AppError::Refused {
        status: StatusCode::BAD_REQUEST,
        code,
        detail: detail.into(),
    }
}

fn warn_skip(ev: &Event, msg: &str) {
    tracing::warn!(event_id = %ev.id, "{msg}");
}

fn ts(v: &Value) -> Option<DateTime<Utc>> {
    v.as_i64().and_then(|s| DateTime::from_timestamp(s, 0))
}

/// Stripe's subscription status as ours; `None` for one we do not track (logged, ignored).
fn status_of(stripe: &str) -> Option<B> {
    Some(match stripe {
        "trialing" => B::Trialing,
        "active" => B::Active,
        "past_due" | "unpaid" => B::PastDue,
        "canceled" | "incomplete_expired" => B::Canceled,
        "incomplete" => B::None,
        _ => return None,
    })
}

/// `POST /v1/webhooks/stripe`: verifies the signature over the raw body (400
/// `bad_signature`), then applies each event once (`stripe_events`), in one transaction with
/// its writes, so a failed write is retried by Stripe rather than lost. Unhandled types and
/// unknown customers are acknowledged and ignored. 503 until the webhook secret is set.
pub struct HandleWebhook {
    uow: Arc<dyn UnitOfWork>,
    clock: Arc<dyn Clock>,
    settings: BillingSettings,
}

impl HandleWebhook {
    pub fn new(uow: Arc<dyn UnitOfWork>, clock: Arc<dyn Clock>, settings: BillingSettings) -> Self {
        Self {
            uow,
            clock,
            settings,
        }
    }

    pub async fn run(&self, signature: Option<&str>, body: &[u8]) -> AppResult<()> {
        if !self.settings.webhook_configured {
            return Err(unavailable());
        }
        let secret = &self.settings.webhook_secret;
        verify_stripe_signature(signature.unwrap_or(""), body, secret, self.clock.now())
            .map_err(|_| bad_request("bad_signature", "Invalid Stripe-Signature."))?;
        let ev: Event = serde_json::from_slice(body)
            .map_err(|_| bad_request("bad_payload", "Not a Stripe event."))?;
        if !HANDLED.contains(&ev.kind.as_str()) {
            return Ok(());
        }
        let created = DateTime::from_timestamp(ev.created, 0)
            .ok_or_else(|| bad_request("bad_payload", "Bad event timestamp."))?;
        let tx = self.uow.begin().await?;
        if !tx.billing().record_event(&ev.id, &ev.kind).await? {
            return Ok(());
        }
        if ev.kind == "checkout.session.completed" {
            self.checkout_completed(tx.as_ref(), &ev).await?;
        } else {
            let customer = ev.data.object["customer"].as_str();
            match customer {
                Some(c) => match tx.billing().org_for_customer(c).await? {
                    Some(org) => self.apply(tx.as_ref(), org, &ev, created).await?,
                    None => warn_skip(&ev, "stripe event for an unknown customer"),
                },
                None => warn_skip(&ev, "stripe event without a customer"),
            }
        }
        tx.commit().await?;
        Ok(())
    }

    /// The customer is saved before Checkout, so this only fills a gap. A session whose
    /// organisation is gone, or whose customer disagrees with what is stored, is ignored.
    async fn checkout_completed(&self, tx: &dyn Tx, ev: &Event) -> AppResult<()> {
        let o = &ev.data.object;
        let org: Option<Uuid> = o["client_reference_id"]
            .as_str()
            .and_then(|r| r.parse().ok());
        let (Some(org), Some(customer)) = (org, o["customer"].as_str()) else {
            warn_skip(ev, "checkout session without organisation or customer");
            return Ok(());
        };
        let repo = tx.billing();
        let stored = match repo.billing(org).await {
            Err(RepoError::NotFound) => {
                warn_skip(ev, "checkout session for an unknown organisation");
                return Ok(());
            }
            r => r?,
        };
        let owner = repo.org_for_customer(customer).await?;
        let theirs = owner.is_some_and(|o| o != org);
        let differs = stored.customer_id.as_deref().is_some_and(|c| c != customer);
        if theirs || differs {
            warn_skip(
                ev,
                "checkout session customer does not match the organisation",
            );
        } else if stored.customer_id.is_none() {
            repo.set_customer(org, customer).await?;
        }
        Ok(())
    }

    async fn apply(
        &self,
        tx: &dyn Tx,
        org: Uuid,
        ev: &Event,
        created: DateTime<Utc>,
    ) -> AppResult<()> {
        let repo = tx.billing();
        let stored = repo.billing(org).await?;
        let paid = match ev.kind.as_str() {
            "invoice.payment_failed" => Some(B::PastDue),
            "invoice.payment_succeeded" => Some(B::Active),
            _ => None,
        };
        if let Some(status) = paid {
            if stored.subscription.is_none() {
                warn_skip(ev, "stripe invoice before any subscription");
                return Ok(());
            }
            // The repo moves only past_due <-> active; a trial's paid $0 invoice is a no-op.
            repo.apply_payment(org, status, created).await?;
            return Ok(());
        }
        match self.subscription(ev, stored.status) {
            Some(s) => {
                let before = stored.subscription.and_then(|o| o.current_period_start);
                let applied = repo.apply_subscription(org, &s, created).await?;
                // A new period: the quantity may come down now, without proration.
                let renewed = (before.is_some() && s.current_period_start != before)
                    .then_some(s.current_period_start)
                    .flatten();
                if let (true, Some(start)) = (applied, renewed) {
                    enqueue_sync(tx, org, start).await?;
                }
            }
            None => warn_skip(ev, "stripe subscription event not applied"),
        }
        Ok(())
    }

    /// The subscription object as our state. The period lives on the one item (Stripe-Version
    /// 2025-09-30.clover). Ending while `stored` is trialing is `trial_ended`.
    fn subscription(&self, ev: &Event, stored: B) -> Option<SubscriptionState> {
        let o = &ev.data.object;
        let item = &o["items"]["data"][0];
        let price = item["price"]["id"].as_str();
        let tier = price.and_then(|p| self.settings.tier_of(p));
        if tier.is_none() {
            let price = price.unwrap_or("");
            tracing::warn!(event_id = %ev.id, price_id = %price, "stripe price matches no tier");
        }
        let status = match status_of(o["status"].as_str()?)? {
            B::Canceled if stored == B::Trialing => B::TrialEnded,
            s => s,
        };
        Some(SubscriptionState {
            subscription_id: o["id"].as_str()?.to_owned(),
            status,
            tier,
            quantity: item["quantity"].as_i64().and_then(|q| q.try_into().ok())?,
            trial_ends_at: ts(&o["trial_end"]),
            current_period_start: ts(&item["current_period_start"]),
            current_period_end: ts(&item["current_period_end"]),
        })
    }
}
