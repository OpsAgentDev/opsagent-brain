use std::sync::Arc;

use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use opsagent_core::{
    billing::{BillingStatus as B, SubscriptionState},
    repo::Clock,
};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use super::{unavailable, BillingSettings};
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
        match self.org_of(tx.as_ref(), &ev).await? {
            Some(org) => self.apply(tx.as_ref(), org, &ev, created).await?,
            None => tracing::warn!(event_id = %ev.id, "stripe event for an unknown customer"),
        }
        tx.commit().await?;
        Ok(())
    }

    /// Checkout names the organisation (`client_reference_id`); everything else carries the
    /// Stripe customer.
    async fn org_of(&self, tx: &dyn Tx, ev: &Event) -> AppResult<Option<Uuid>> {
        let o = &ev.data.object;
        let by_ref = o["client_reference_id"]
            .as_str()
            .and_then(|r| r.parse().ok());
        if let Some(org) = by_ref.filter(|_| ev.kind == "checkout.session.completed") {
            return Ok(Some(org));
        }
        match o["customer"].as_str() {
            Some(c) => Ok(tx.billing().org_for_customer(c).await?),
            None => Ok(None),
        }
    }

    async fn apply(
        &self,
        tx: &dyn Tx,
        org: Uuid,
        ev: &Event,
        created: DateTime<Utc>,
    ) -> AppResult<()> {
        let o = &ev.data.object;
        let repo = tx.billing();
        let stored = repo.billing(org).await?;
        let next = match ev.kind.as_str() {
            "checkout.session.completed" => {
                // The customer is saved before Checkout; this only fills a gap.
                if let (None, Some(c)) = (&stored.customer_id, o["customer"].as_str()) {
                    repo.set_customer(org, c).await?;
                }
                return Ok(());
            }
            "invoice.payment_failed" if stored.status.is_subscribed() => {
                stored.subscription.map(|s| SubscriptionState {
                    status: B::PastDue,
                    ..s
                })
            }
            // A trial's $0 invoice is paid too; only a payment that ends arrears counts.
            "invoice.payment_succeeded" if matches!(stored.status, B::PastDue | B::Paused) => {
                stored.subscription.map(|s| SubscriptionState {
                    status: B::Active,
                    ..s
                })
            }
            k if k.starts_with("customer.subscription.") => self.subscription(o, stored.status),
            _ => None,
        };
        if let Some(s) = next {
            repo.apply_subscription(org, &s, created).await?;
        } else if ev.kind.starts_with("customer.subscription.") {
            tracing::warn!(event_id = %ev.id, "stripe subscription event not applied");
        }
        Ok(())
    }

    /// The subscription object as our state. The period lives on the one item (Stripe-Version
    /// 2025-09-30.clover). Ending while `stored` is trialing is `trial_ended`.
    fn subscription(&self, o: &Value, stored: B) -> Option<SubscriptionState> {
        let item = &o["items"]["data"][0];
        let status = match status_of(o["status"].as_str()?)? {
            B::Canceled if stored == B::Trialing => B::TrialEnded,
            s => s,
        };
        Some(SubscriptionState {
            subscription_id: o["id"].as_str()?.to_owned(),
            status,
            tier: item["price"]["id"]
                .as_str()
                .and_then(|p| self.settings.tier_of(p)),
            quantity: item["quantity"].as_i64().and_then(|q| q.try_into().ok())?,
            trial_ends_at: ts(&o["trial_end"]),
            current_period_start: ts(&item["current_period_start"]),
            current_period_end: ts(&item["current_period_end"]),
        })
    }
}
