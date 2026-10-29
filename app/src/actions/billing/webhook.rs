use std::sync::Arc;

use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use opsagent_core::{
    billing::{BillingError, BillingProvider, BillingStatus as B, SubscriptionState},
    repo::{Clock, RepoError},
};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use super::{provider_failed, unavailable, BillingSettings};
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

/// The invoice's subscription: `parent.subscription_details.subscription` (Stripe-Version
/// 2025-09-30.clover), else the older top-level `subscription`.
fn invoice_subscription(o: &Value) -> Option<&str> {
    o["parent"]["subscription_details"]["subscription"]
        .as_str()
        .or_else(|| o["subscription"].as_str())
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
    provider: Arc<dyn BillingProvider>,
    clock: Arc<dyn Clock>,
    settings: BillingSettings,
}

impl HandleWebhook {
    pub fn new(
        uow: Arc<dyn UnitOfWork>,
        provider: Arc<dyn BillingProvider>,
        clock: Arc<dyn Clock>,
        settings: BillingSettings,
    ) -> Self {
        Self {
            uow,
            provider,
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
                    Some(org) => match self.apply(tx.as_ref(), org, &ev, created).await {
                        Err(AppError::Repo(RepoError::NotFound)) => {
                            warn_skip(&ev, "stripe event for an organisation that is gone");
                        }
                        r => r?,
                    },
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
            let Some(sub) = stored.subscription.as_ref() else {
                warn_skip(ev, "stripe invoice before any subscription");
                return Ok(());
            };
            if invoice_subscription(&ev.data.object) != Some(sub.subscription_id.as_str()) {
                warn_skip(ev, "stripe invoice for another subscription");
                return Ok(());
            }
            // The repo moves only past_due <-> active; a trial's paid $0 invoice is a no-op.
            repo.apply_payment(org, status, created).await?;
            return Ok(());
        }
        let Some(s) = self.subscription(ev, stored.status) else {
            warn_skip(ev, "stripe subscription event not applied");
            return Ok(());
        };
        match stored
            .subscription
            .filter(|_| stored.status.is_subscribed())
        {
            Some(kept) if kept.subscription_id != s.subscription_id => {
                self.second_subscription(ev, &kept.subscription_id, &s)
                    .await
            }
            _ => repo
                .apply_subscription(org, &s, created)
                .await
                .map(|_| ())
                .map_err(Into::into),
        }
    }

    /// An event for a subscription other than the organisation's live one is not applied; a
    /// live one would bill the organisation twice, so it is cancelled (idempotent on its id).
    async fn second_subscription(
        &self,
        ev: &Event,
        kept: &str,
        s: &SubscriptionState,
    ) -> AppResult<()> {
        let other = s.subscription_id.as_str();
        if !s.status.is_subscribed() {
            warn_skip(ev, "stripe event for an ended second subscription");
            return Ok(());
        }
        tracing::error!(
            event_id = %ev.id, kept_subscription_id = %kept, cancelled_subscription_id = %other,
            "second live stripe subscription for an organisation; cancelling it"
        );
        let idem = format!("billing:cancel:{other}");
        match self.provider.cancel_subscription(other, &idem).await {
            Ok(()) | Err(BillingError::NotFound) => Ok(()),
            Err(e) => Err(provider_failed(e)),
        }
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

#[cfg(test)]
mod tests {
    use hmac::{Hmac, Mac};
    use opsagent_core::billing::BillingRepo;
    use serde_json::json;
    use sha2::Sha256;

    use super::*;
    use crate::{
        actions::{
            billing::nightly::tests::{settings, NoStripe},
            orgs::test_support::owned_org,
        },
        adapters::memory::{FixedClock, MemStore},
    };

    #[tokio::test]
    async fn event_for_an_organisation_gone_mid_way_is_acknowledged() {
        let store = MemStore::default();
        let (_, org) = owned_org(&store, "o@example.com", "Acme").await;
        store.set_customer(org.id, "cus_1").await.unwrap();
        store.forget_org(org.id);
        let now = Utc::now();
        let item = json!({ "quantity": 1, "price": { "id": "p_t" } });
        let object = json!({ "id": "sub_1", "customer": "cus_1", "status": "active",
            "items": { "data": [item] } });
        let body = json!({ "id": "evt_1", "type": "customer.subscription.updated",
            "created": now.timestamp(), "data": { "object": object } })
        .to_string();
        let mut m = Hmac::<Sha256>::new_from_slice(b"whsec").unwrap();
        m.update(format!("{}.{body}", now.timestamp()).as_bytes());
        let v1: String = m
            .finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let sig = format!("t={},v1={v1}", now.timestamp());
        let hook = HandleWebhook::new(
            Arc::new(store.clone()),
            Arc::new(NoStripe),
            Arc::new(FixedClock(now)),
            settings(),
        );
        hook.run(Some(&sig), body.as_bytes()).await.unwrap();
        // Recorded with the transaction, so Stripe's redelivery is a no-op.
        assert!(!store.record_event("evt_1", "x").await.unwrap());
    }
}
