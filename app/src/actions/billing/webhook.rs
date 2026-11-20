use std::sync::Arc;

use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use opsagent_core::{
    audit::AuditEntry,
    billing::{BillingError, BillingProvider, BillingStatus as B, SubscriptionState},
    repo::{Clock, RepoError},
};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use super::{enqueue_sync, provider_failed, unavailable, BillingSettings};
use crate::{
    actions::{
        day_counts::{Counted, DayCounter},
        human_reviews::enqueue_notice,
        uow::{Tx, UnitOfWork},
    },
    adapters::stripe::{verify_stripe_signature, HUMAN_REVIEW_PURPOSE, TOPUP_PURPOSE},
    error::{AppError, AppResult},
};

const HANDLED: [&str; 10] = [
    "charge.dispute.closed",
    "charge.dispute.created",
    "charge.refunded",
    "checkout.session.completed",
    "checkout.session.async_payment_succeeded",
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
    /// The version Stripe rendered this event in (the endpoint's pin, else the account default).
    #[serde(default)]
    api_version: Option<String>,
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

/// Credits one top-up buys (dashboard-ai.md, Top-ups).
const TOPUP_CREDITS: i64 = 1000;

/// What a top-up payment's refund and dispute events record, in `held_back`'s order: fully
/// refunded, disputed, dispute won.
const PAYMENT_MARKS: [&str; 3] = ["reversal:refund", "reversal:dispute", "restore:dispute"];

/// Whether a top-up payment's credits are taken back: it is fully refunded, or it has a
/// dispute that is not won.
fn held_back([refunded, disputed, won]: [bool; 3]) -> bool {
    refunded || (disputed && !won)
}

/// A paid top-up session adds its credits to the organisation named by
/// `client_reference_id`, once per event (`grant_topup` is keyed on it, like `record_event`).
/// True when a paid session matched no organisation (counted for the operator notice).
async fn topup_completed(tx: &dyn Tx, ev: &Event) -> AppResult<bool> {
    let o = &ev.data.object;
    let org: Option<Uuid> = o["client_reference_id"]
        .as_str()
        .and_then(|r| r.parse().ok());
    let Some(org) = org else {
        warn_skip(ev, "top-up session without organisation");
        return Ok(o["payment_status"] == "paid");
    };
    // A delayed payment method completes unpaid; its `async_payment_succeeded` grants instead.
    if o["payment_status"] != "paid" {
        warn_skip(ev, "top-up session not paid");
        return Ok(false);
    }
    let credits = sea_orm::prelude::Decimal::from(TOPUP_CREDITS);
    match tx.ai().grant_topup(org, credits, &ev.id).await {
        Err(RepoError::NotFound) => {
            warn_skip(ev, "top-up session for an unknown organisation");
            Ok(true)
        }
        r => {
            r?;
            Ok(false)
        }
    }
}

/// A paid human review session marks its request paid, once: `mark_paid` flips only a
/// `pending` row of the organisation named by `client_reference_id`, and queues its notice
/// (human_reviews::enqueue_notice) in the same transaction.
/// True when a paid session matched no request (counted for the operator notice).
async fn review_paid(tx: &dyn Tx, ev: &Event, now: DateTime<Utc>) -> AppResult<bool> {
    let o = &ev.data.object;
    let uuid = |v: &Value| v.as_str().and_then(|r| r.parse::<Uuid>().ok());
    let (org, id) = (
        uuid(&o["client_reference_id"]),
        uuid(&o["metadata"]["review_request_id"]),
    );
    let (Some(org), Some(id)) = (org, id) else {
        warn_skip(ev, "human review session without organisation or request");
        return Ok(o["payment_status"] == "paid");
    };
    if o["payment_status"] != "paid" {
        warn_skip(ev, "human review session not paid");
        return Ok(false);
    }
    let Some(review) = tx.human_reviews().mark_paid(org, id, now).await? else {
        warn_skip(
            ev,
            "human review session for an unknown or already paid request",
        );
        return Ok(true);
    };
    enqueue_notice(tx, org, &review).await?;
    Ok(false)
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
/// unknown customers are acknowledged and ignored. A paid human review commits with its
/// notice job, which sends the mails (never the webhook). A refunded or disputed top-up
/// gives its credits back, and a dispute won restores them (`topup_charge`).
/// 503 until the webhook secret is set.
pub struct HandleWebhook {
    uow: Arc<dyn UnitOfWork>,
    provider: Arc<dyn BillingProvider>,
    clock: Arc<dyn Clock>,
    settings: BillingSettings,
    counter: DayCounter,
}

impl HandleWebhook {
    pub fn new(
        uow: Arc<dyn UnitOfWork>,
        provider: Arc<dyn BillingProvider>,
        clock: Arc<dyn Clock>,
        settings: BillingSettings,
        counter: DayCounter,
    ) -> Self {
        Self {
            uow,
            provider,
            clock,
            settings,
            counter,
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
        // The parser reads that version's shape; a mismatch is logged rather than refused,
        // since newer versions have kept the fields read here. Pin the endpoint to fix it.
        if let Some(v) = ev
            .api_version
            .as_deref()
            .filter(|v| *v != self.settings.api_version)
        {
            tracing::warn!(
                error_code = "stripe_api_version_mismatch",
                event_id = %ev.id,
                got = v,
                expected = %self.settings.api_version,
                "stripe webhook event in an unexpected api version"
            );
        }
        let created = DateTime::from_timestamp(ev.created, 0)
            .ok_or_else(|| bad_request("bad_payload", "Bad event timestamp."))?;
        let tx = self.uow.begin().await?;
        if !tx.billing().record_event(&ev.id, &ev.kind).await? {
            return Ok(());
        }
        let o = &ev.data.object;
        let purpose = (o["mode"] == "payment").then(|| o["metadata"]["purpose"].as_str());
        let paid_event = matches!(
            ev.kind.as_str(),
            "checkout.session.completed" | "checkout.session.async_payment_succeeded"
        );
        let mut unmatched = false;
        if paid_event && purpose == Some(Some(TOPUP_PURPOSE)) {
            unmatched = topup_completed(tx.as_ref(), &ev).await?;
        } else if paid_event && purpose == Some(Some(HUMAN_REVIEW_PURPOSE)) {
            unmatched = review_paid(tx.as_ref(), &ev, self.clock.now()).await?;
        } else if ev.kind == "checkout.session.completed" {
            self.checkout_completed(tx.as_ref(), &ev).await?;
        } else if paid_event {
            // A subscription's delayed payment: its subscription events carry the state.
        } else if ev.kind.starts_with("charge.") {
            unmatched = self.topup_charge(tx.as_ref(), &ev).await?;
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
        // After the commit: an event Stripe has to send again is counted once.
        let counter = &self.counter;
        counter
            .add(Counted::UnmatchedPayment, u64::from(unmatched))
            .await;
        Ok(())
    }

    /// Refunds and disputes of a top-up payment. Its credits are held back while the payment
    /// is fully refunded or has a dispute that is not won (`held_back`). Each event records
    /// its own marker for the payment (`PAYMENT_MARKS`, a grant keyed `<mark>:<payment
    /// intent>`) carrying only the difference it makes, so whatever the order, the repeats
    /// and the mix of causes, one payment never gives back more than it granted or less than
    /// its state requires. The balance may go below 0 (owed from the next top-up). A partial
    /// refund, a dispute closed any other way than `won`, and any other charge (a
    /// subscription's, a human review's) change nothing. The payment is matched through its
    /// Checkout session (the provider), so a failed lookup fails the webhook and Stripe sends
    /// the event again.
    /// True when a top-up's refund or dispute matched no organisation (counted for the
    /// operator notice).
    async fn topup_charge(&self, tx: &dyn Tx, ev: &Event) -> AppResult<bool> {
        let o = &ev.data.object;
        let (mark, reason) = match ev.kind.as_str() {
            // `refunded` is true only once all of the charge is refunded.
            "charge.refunded" if o["refunded"] == true => (0, "refund"),
            "charge.dispute.created" => (1, "dispute"),
            "charge.dispute.closed" if o["status"] == "won" => (2, "dispute_won"),
            _ => return Ok(false),
        };
        let Some(payment) = o["payment_intent"].as_str() else {
            return Ok(false);
        };
        let reference = match self.provider.topup_of_payment(payment).await {
            Ok(Some(r)) => r,
            Ok(None) | Err(BillingError::NotFound) => return Ok(false),
            Err(e) => return Err(provider_failed(e)),
        };
        let org = reference.parse::<Uuid>().ok();
        let known = match org {
            Some(org) => !matches!(tx.billing().billing(org).await, Err(RepoError::NotFound)),
            None => false,
        };
        let Some(org) = org.filter(|_| known) else {
            warn_skip(ev, "top-up refund or dispute matches no organisation");
            // Counted when credits could not be taken back; a won dispute takes none.
            return Ok(mark != 2);
        };
        // One at a time per organisation: two events of one payment must see each other's mark.
        tx.orgs().lock(org).await?;
        let key = |m: usize| format!("{}:{payment}", PAYMENT_MARKS[m]);
        let mut marks = [false; 3];
        for (m, set) in marks.iter_mut().enumerate() {
            *set = tx.ai().has_grant(org, &key(m)).await?;
        }
        let before = held_back(marks);
        marks[mark] = true;
        let credits = sea_orm::prelude::Decimal::from(TOPUP_CREDITS);
        let (change, action) = match (before, held_back(marks)) {
            (false, true) => (-credits, "ai.topup_reversed"),
            (true, false) => (credits, "ai.topup_restored"),
            _ => (0.into(), ""),
        };
        if tx.ai().grant_topup(org, change, &key(mark)).await? && !change.is_zero() {
            let target = ("payment", payment.to_owned());
            let entry = AuditEntry::system(org, action, target, "success")
                .with_meta(serde_json::json!({ "credits": TOPUP_CREDITS, "reason": reason }));
            tx.audit().record(entry).await?;
        }
        Ok(false)
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
            _ => {
                let applied = repo.apply_subscription(org, &s, created).await?;
                // A trial just started: the organisation's run mails its owners
                // (nightly::trial_started_notice), so the mail never holds up the webhook.
                if applied && s.status == B::Trialing && stored.status != B::Trialing {
                    enqueue_sync(tx, org, created).await?;
                }
                Ok(())
            }
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
            // Stripe sets one or the other depending on how the cancellation was made.
            cancel_at_period_end: o["cancel_at_period_end"].as_bool().unwrap_or(false)
                || !o["cancel_at"].is_null(),
        })
    }
}

#[cfg(test)]
mod tests {
    use hmac::{Hmac, KeyInit, Mac};
    use opsagent_core::{ai::AiRepo, billing::BillingRepo};
    use serde_json::json;
    use sha2::Sha256;

    use super::*;
    use crate::{
        actions::ai::CreditTally,
        actions::{
            billing::nightly::tests::{settings, NoStripe},
            orgs::test_support::owned_org,
        },
        adapters::memory::{FixedClock, MemRateLimiter, MemStore},
    };

    /// A `customer.subscription.*` event for `cus_1` at `now`, and its signature.
    fn sub_event(id: &str, status: &str, now: DateTime<Utc>) -> (String, String) {
        let item = json!({ "quantity": 1, "price": { "id": "p_t" } });
        let trial_end = (now + chrono::Duration::days(14)).timestamp();
        let object = json!({ "id": "sub_1", "customer": "cus_1", "status": status,
            "trial_end": trial_end, "items": { "data": [item] } });
        let body = json!({ "id": id, "type": "customer.subscription.updated",
            "created": now.timestamp(), "data": { "object": object } })
        .to_string();
        (sign(&body, now), body)
    }

    fn sign(body: &str, now: DateTime<Utc>) -> String {
        let mut m = Hmac::<Sha256>::new_from_slice(b"whsec").unwrap();
        m.update(format!("{}.{body}", now.timestamp()).as_bytes());
        let v1: String = m
            .finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("t={},v1={v1}", now.timestamp())
    }

    fn hook(store: &MemStore, now: DateTime<Utc>) -> HandleWebhook {
        let tally = Arc::new(MemRateLimiter::default());
        hook_counting(store, now, tally, NoStripe::default())
    }

    fn hook_counting(
        store: &MemStore,
        now: DateTime<Utc>,
        tally: Arc<MemRateLimiter>,
        stripe: NoStripe,
    ) -> HandleWebhook {
        let clock = Arc::new(FixedClock(now));
        HandleWebhook::new(
            Arc::new(store.clone()),
            Arc::new(stripe),
            clock.clone(),
            settings(),
            DayCounter::new(tally, clock),
        )
    }

    #[tokio::test]
    async fn a_paid_session_that_matches_nothing_is_counted_for_the_operator() {
        let (store, now) = (MemStore::default(), Utc::now());
        let tally = Arc::new(MemRateLimiter::default());
        let h = hook_counting(&store, now, tally.clone(), NoStripe::default());
        let nobody = Uuid::new_v4().to_string();
        let session = |id: &str, purpose: &str, paid: &str| {
            let object = json!({ "mode": "payment", "payment_status": paid,
                "client_reference_id": nobody,
                "metadata": { "purpose": purpose, "review_request_id": nobody } });
            json!({ "id": id, "type": "checkout.session.completed",
                "created": now.timestamp(), "data": { "object": object } })
            .to_string()
        };
        let key = format!("payment:unmatched:{}", now.date_naive());
        // Not paid yet: nothing was lost, nothing is counted.
        let unpaid = session("evt_0", TOPUP_PURPOSE, "unpaid");
        h.run(Some(&sign(&unpaid, now)), unpaid.as_bytes())
            .await
            .unwrap();
        assert_eq!(tally.total(&key).await.unwrap(), 0.into());
        for (id, purpose) in [("evt_1", TOPUP_PURPOSE), ("evt_2", HUMAN_REVIEW_PURPOSE)] {
            let body = session(id, purpose, "paid");
            let sig = sign(&body, now);
            h.run(Some(&sig), body.as_bytes()).await.unwrap();
            // A repeat of the event is not counted again.
            h.run(Some(&sig), body.as_bytes()).await.unwrap();
        }
        assert_eq!(tally.total(&key).await.unwrap(), 2.into());
    }

    #[tokio::test]
    async fn event_for_an_organisation_gone_mid_way_is_acknowledged() {
        let store = MemStore::default();
        let (_, org) = owned_org(&store, "o@example.com", "Acme").await;
        store.set_customer(org.id, "cus_1").await.unwrap();
        store.forget_org(org.id);
        let now = Utc::now();
        let (sig, body) = sub_event("evt_1", "active", now);
        let hook = hook(&store, now);
        hook.run(Some(&sig), body.as_bytes()).await.unwrap();
        // Recorded with the transaction, so Stripe's redelivery is a no-op.
        assert!(!store.record_event("evt_1", "x").await.unwrap());
    }

    /// The webhook sends no mail itself (it has no mailer): the trial's start queues the
    /// organisation's `billing_sync` run, which mails the owners, so mail can never fail it.
    #[tokio::test]
    async fn a_trial_starting_queues_its_notice_run_once() {
        let store = MemStore::default();
        let (_, org) = owned_org(&store, "o@example.com", "Acme").await;
        store.set_customer(org.id, "cus_1").await.unwrap();
        let now = Utc::now();
        let hook = hook(&store, now);
        // The same event again, then a later one of the same trial: one run, queued once.
        for (id, secs) in [("evt_1", 0), ("evt_1", 0), ("evt_2", 60)] {
            let at = now + chrono::Duration::seconds(secs);
            let (sig, body) = sub_event(id, "trialing", at);
            hook.run(Some(&sig), body.as_bytes()).await.unwrap();
        }
        let jobs = store.jobs();
        assert_eq!(jobs.len(), 1, "{jobs:?}");
        assert_eq!(jobs[0].kind, opsagent_ledger::JobKind::BillingSync);
        assert_eq!(store.billing(org.id).await.unwrap().status, B::Trialing);
    }

    /// Delivers a charge event about payment `pi`: a refund (fully, when `full`) or a dispute.
    async fn charge(h: &HandleWebhook, id: &str, kind: &str, pi: &str, full: bool) {
        let now = h.clock.now();
        // `status` is read on a closed dispute only: won when `full`, else lost.
        let status = if full { "won" } else { "lost" };
        let object = json!({ "customer": "cus_1", "payment_intent": pi, "refunded": full,
            "status": status });
        let body = json!({ "id": id, "type": kind, "created": now.timestamp(),
            "data": { "object": object } })
        .to_string();
        h.run(Some(&sign(&body, now)), body.as_bytes())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_refunded_or_disputed_topup_gives_its_credits_back_once() {
        let (store, now) = (MemStore::default(), Utc::now());
        let (_, org) = owned_org(&store, "o@example.com", "Acme").await;
        let tally = Arc::new(MemRateLimiter::default());
        let paid_by = NoStripe(Some(org.id.to_string()));
        let h = hook_counting(&store, now, tally.clone(), paid_by);
        let credits = sea_orm::prelude::Decimal::from(TOPUP_CREDITS);
        let granted = store.grant_topup(org.id, credits, "evt_grant");
        assert!(granted.await.unwrap());
        let balance = || async { store.topup_balance(org.id).await.unwrap() };
        // A partial refund keeps the credits.
        charge(&h, "evt_1", "charge.refunded", "pi_1", false).await;
        assert_eq!(balance().await, credits);
        // The full refund, its redelivery, then a dispute of the same payment: taken back once.
        for (id, kind) in [
            ("evt_2", "charge.refunded"),
            ("evt_2", "charge.refunded"),
            ("evt_3", "charge.dispute.created"),
        ] {
            charge(&h, id, kind, "pi_1", true).await;
            assert_eq!(balance().await, 0.into(), "{id}");
        }
        // Credits already spent are owed: another payment's dispute takes the balance below 0.
        charge(&h, "evt_4", "charge.dispute.created", "pi_2", false).await;
        assert_eq!(balance().await, -credits);
        let all = store.audit_entries();
        let reversed = all.iter().filter(|e| e.action == "ai.topup_reversed");
        let seen: Vec<_> = reversed
            .map(|e| (e.organisation_id, e.meta["reason"].as_str()))
            .collect();
        let org = Some(org.id);
        assert_eq!(seen, [(org, Some("refund")), (org, Some("dispute"))]);
        let key = format!("payment:unmatched:{}", now.date_naive());
        assert_eq!(tally.total(&key).await.unwrap(), 0.into());
    }

    #[tokio::test]
    async fn a_dispute_won_restores_the_reversed_credits_once() {
        let (store, now) = (MemStore::default(), Utc::now());
        let (_, org) = owned_org(&store, "o@example.com", "Acme").await;
        let tally = Arc::new(MemRateLimiter::default());
        let h = hook_counting(&store, now, tally, NoStripe(Some(org.id.to_string())));
        let credits = sea_orm::prelude::Decimal::from(TOPUP_CREDITS);
        let balance = || async { store.topup_balance(org.id).await.unwrap() };
        const CLOSED: &str = "charge.dispute.closed";
        charge(&h, "evt_1", "charge.dispute.created", "pi_1", false).await;
        assert_eq!(balance().await, -credits);
        // Lost: the credits stay taken back.
        charge(&h, "evt_2", CLOSED, "pi_1", false).await;
        assert_eq!(balance().await, -credits);
        // Won, its redelivery, and a second won event: restored once.
        for id in ["evt_3", "evt_3", "evt_4"] {
            charge(&h, id, CLOSED, "pi_1", true).await;
            assert_eq!(balance().await, 0.into(), "{id}");
        }
        let all = store.audit_entries();
        let restored: Vec<_> = (all.iter())
            .filter(|e| e.action == "ai.topup_restored")
            .map(|e| (e.organisation_id, e.meta["reason"].as_str()))
            .collect();
        assert_eq!(restored, [(Some(org.id), Some("dispute_won"))]);
    }

    /// Every sequence of up to four of a payment's events, each delivered twice: whatever the
    /// order and the repeats, the credits are out exactly when the payment is fully refunded
    /// or has a dispute that was not won.
    #[tokio::test]
    async fn every_order_of_refund_and_dispute_events_nets_to_the_payment_state() {
        // (kind, `charge`'s flag): refund in full, dispute opened, dispute won, dispute lost.
        const EVENTS: [(&str, bool); 4] = [
            ("charge.refunded", true),
            ("charge.dispute.created", false),
            ("charge.dispute.closed", true),
            ("charge.dispute.closed", false),
        ];
        let now = Utc::now();
        let credits = sea_orm::prelude::Decimal::from(TOPUP_CREDITS);
        for len in 1..=4u32 {
            for code in 0..4usize.pow(len) {
                let seq: Vec<usize> = (0..len).map(|i| code / 4usize.pow(i) % 4).collect();
                let store = MemStore::default();
                let (_, org) = owned_org(&store, "o@example.com", "Acme").await;
                let tally = Arc::new(MemRateLimiter::default());
                let h = hook_counting(&store, now, tally, NoStripe(Some(org.id.to_string())));
                assert!(store
                    .grant_topup(org.id, credits, "evt_grant")
                    .await
                    .unwrap());
                for (i, e) in seq.iter().enumerate() {
                    let (kind, flag) = EVENTS[*e];
                    for _ in 0..2 {
                        charge(&h, &format!("evt_{i}"), kind, "pi_1", flag).await;
                    }
                }
                let has = |e: usize| seq.contains(&e);
                let out = has(0) || (has(1) && !has(2));
                let want = if out { 0.into() } else { credits };
                let got = store.topup_balance(org.id).await.unwrap();
                assert_eq!(got, want, "events {seq:?}");
            }
        }
    }

    #[tokio::test]
    async fn only_a_topup_that_matches_no_organisation_is_counted() {
        let (store, now) = (MemStore::default(), Utc::now());
        let (_, org) = owned_org(&store, "o@example.com", "Acme").await;
        store.set_customer(org.id, "cus_1").await.unwrap();
        let before = store.billing(org.id).await.unwrap();
        let tally = Arc::new(MemRateLimiter::default());
        let key = format!("payment:unmatched:{}", now.date_naive());
        // A subscription's (or a human review's) charge: accepted, nothing changes.
        let h = hook_counting(&store, now, tally.clone(), NoStripe(None));
        for kind in ["charge.refunded", "charge.dispute.created"] {
            charge(&h, kind, kind, "pi_sub", true).await;
        }
        assert_eq!(store.billing(org.id).await.unwrap(), before);
        assert_eq!(store.topup_balance(org.id).await.unwrap(), 0.into());
        assert_eq!(tally.total(&key).await.unwrap(), 0.into());
        // A top-up whose organisation is gone: accepted and counted once, its repeat too.
        for reference in [Uuid::new_v4().to_string(), String::new()] {
            let h = hook_counting(
                &store,
                now,
                tally.clone(),
                NoStripe(Some(reference.clone())),
            );
            let id = format!("evt_{reference}");
            charge(&h, &id, "charge.refunded", "pi_gone", true).await;
            charge(&h, &id, "charge.refunded", "pi_gone", true).await;
        }
        assert_eq!(tally.total(&key).await.unwrap(), 2.into());
        let all = store.audit_entries();
        assert!(all.iter().all(|e| e.action != "ai.topup_reversed"));
    }
}
