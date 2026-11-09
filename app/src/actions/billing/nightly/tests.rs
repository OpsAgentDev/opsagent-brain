use std::sync::Arc;

use async_trait::async_trait;
use chrono::TimeZone;
use opsagent_core::billing::{
    BillingProvider, BillingRepo, BillingResult, CheckoutRequest, ReviewCheckout, SubscriptionState,
};
use opsagent_core::{audit::Actor, org::OrganisationsRepo, org::Role};
use opsagent_ledger::redis;

use super::*;
use crate::{
    actions::{
        billing::BillingSettings,
        orgs::test_support::{owned_org, user},
        recipients::MailGuard,
        runs::test_support::connected,
        uow::Repos,
    },
    adapters::memory::{FixedClock, MemRateLimiter, MemStore},
    mailers::CaptureMailer,
};

/// The nightly pass makes no Stripe calls.
pub(in crate::actions::billing) struct NoStripe;

#[async_trait]
impl BillingProvider for NoStripe {
    async fn create_customer(&self, _: Uuid, _: &str, _: &str, _: &str) -> BillingResult<String> {
        unreachable!()
    }
    async fn checkout_session(&self, _: &CheckoutRequest, _: &str) -> BillingResult<String> {
        unreachable!()
    }
    async fn portal_session(&self, _: &str, _: &str) -> BillingResult<String> {
        unreachable!()
    }
    async fn human_review_session(&self, _: &ReviewCheckout, _: &str) -> BillingResult<String> {
        unreachable!()
    }
    async fn topup_session(
        &self,
        _: &str,
        _: Uuid,
        _: &str,
        _: &str,
        _: &str,
    ) -> BillingResult<String> {
        unreachable!()
    }
    async fn set_quantity(&self, _: &str, _: i32, _: bool, _: &str) -> BillingResult<()> {
        unreachable!()
    }
    async fn cancel_subscription(&self, _: &str, _: &str) -> BillingResult<()> {
        unreachable!()
    }
}

pub(in crate::actions::billing) fn settings() -> BillingSettings {
    BillingSettings {
        stripe_configured: true,
        webhook_configured: true,
        webhook_secret: "whsec".into(),
        price_starter: "p_s".into(),
        price_team: "p_t".into(),
        price_scale: "p_x".into(),
        web_base_url: "https://opsagent.test/".into(),
        enforced: false,
    }
}

fn sync(store: &MemStore, mail: &Arc<CaptureMailer>, now: DateTime<Utc>) -> BillingSync {
    let uow = Arc::new(store.clone());
    let guard = Arc::new(MailGuard::new(
        uow.clone(),
        Arc::new(MemRateLimiter::default()),
    ));
    BillingSync::new(
        uow,
        redis::Client::open("redis://localhost:1").unwrap(),
        Arc::new(NoStripe),
        (mail.clone(), guard),
        Arc::new(FixedClock(now)),
        settings(),
    )
}

fn sub(status: B, ends: DateTime<Utc>) -> SubscriptionState {
    SubscriptionState {
        subscription_id: "sub_1".into(),
        status,
        tier: Some(Tier::Team),
        quantity: 1,
        trial_ends_at: Some(ends),
        current_period_start: Some(ends - Duration::days(14)),
        current_period_end: Some(ends),
        cancel_at_period_end: false,
    }
}

async fn night(store: &MemStore, mail: &Arc<CaptureMailer>, now: DateTime<Utc>) {
    let st = sync(store, mail, now)
        .nightly(Uuid::new_v4(), now)
        .await
        .unwrap();
    assert_eq!(st["failed"], 0, "{st}");
}

#[test]
fn reminder_days() {
    let ends = Utc.with_ymd_and_hms(2026, 11, 12, 10, 0, 0).unwrap();
    let at = |h: i64| reminder_day(ends, ends - Duration::hours(h));
    assert_eq!(at(3 * 24 + 1), None); // day 11
    assert_eq!(at(2 * 24 + 1), Some(12));
    assert_eq!(at(24 + 1), Some(12)); // day 13: a missed day-12 reminder still goes
    assert_eq!(at(1), Some(14));
    assert_eq!(at(0), None);
}

#[tokio::test]
async fn a_cancelled_trial_gets_no_reminder() {
    let (store, mail) = (MemStore::default(), Arc::new(CaptureMailer::default()));
    let (_, org) = owned_org(&store, "o@example.com", "Acme").await;
    let ends = Utc.with_ymd_and_hms(2026, 11, 12, 10, 0, 0).unwrap();
    let s = SubscriptionState {
        cancel_at_period_end: true,
        ..sub(B::Trialing, ends)
    };
    store
        .apply_subscription(org.id, &s, ends - Duration::days(14))
        .await
        .unwrap();
    night(&store, &mail, ends - Duration::hours(6)).await;
    assert!(mail.sent().is_empty());
}

#[tokio::test]
async fn trial_reminders_day_12_and_14_once() {
    let (store, mail) = (MemStore::default(), Arc::new(CaptureMailer::default()));
    let (_, org) = owned_org(&store, "o@example.com", "Acme").await;
    let second = user(&store, "p@example.com").await;
    store
        .add_member(org.id, second.id, Role::Owner)
        .await
        .unwrap();
    let ends = Utc.with_ymd_and_hms(2026, 11, 12, 10, 0, 0).unwrap();
    let s = sub(B::Trialing, ends);
    store
        .apply_subscription(org.id, &s, ends - Duration::days(14))
        .await
        .unwrap();
    let hours = |h: i64| ends - Duration::hours(h);
    let mut sent = vec![];
    for h in [3 * 24 + 6, 2 * 24 + 6, 2 * 24 + 5, 24 + 6, 6, 5] {
        night(&store, &mail, hours(h)).await;
        sent.push(mail.sent().len());
    }
    // Each reminder once to each of the two owners.
    assert_eq!(sent, [0, 2, 2, 2, 4, 4]);
    let m = mail.sent();
    let to: Vec<_> = m.iter().map(|m| m.to.as_str()).collect();
    assert_eq!(
        to,
        [
            "o@example.com",
            "p@example.com",
            "o@example.com",
            "p@example.com"
        ]
    );
    assert_eq!(m[0].subject, "Your OpsAgent trial ends on 12 November 2026");
    assert_eq!(
        m[0].text.lines().next().unwrap(),
        "Your free trial ends on 12 November 2026. After that you'll be charged $299 a month \
         unless you change plan or cancel before then."
    );
    // Day 14 says it is the last reminder, in its own words.
    assert_eq!(m[2].subject, "Your OpsAgent trial ends today");
    assert!(m[2]
        .text
        .starts_with("Your free trial ends today (12 November 2026). This is the last reminder."));
    assert!(m[0]
        .text
        .ends_with("https://opsagent.test/settings/billing"));
    let html = m[0].html.as_deref().unwrap();
    assert!(
        html.contains("OpsAgent")
            && html.contains("href=\"https://opsagent.test/settings/billing\"")
    );
    let keys: std::collections::HashSet<_> = m.iter().map(|m| &m.idempotency_key).collect();
    assert_eq!(keys.len(), 4);
    // Converted: no more reminders for an active subscription.
    let active = sub(B::Active, ends);
    store
        .apply_subscription(org.id, &active, ends)
        .await
        .unwrap();
    night(&store, &mail, hours(1)).await;
    assert_eq!(mail.sent().len(), 4);
}

#[tokio::test]
async fn revoked_before_renewal_is_disconnected_and_audited() {
    let (store, mail) = (MemStore::default(), Arc::new(CaptureMailer::default()));
    let (_, org) = owned_org(&store, "o@example.com", "Acme").await;
    let ends = Utc.with_ymd_and_hms(2026, 11, 12, 10, 0, 0).unwrap();
    let s = sub(B::Active, ends);
    store
        .apply_subscription(org.id, &s, ends - Duration::days(14))
        .await
        .unwrap();
    // Revoked inside the stored period: kept until the renewal is within 50 hours.
    let c = connected(&store, org.id).await;
    let repo = store.connections();
    assert!(repo
        .cas_status(org.id, c.id, S::Connected, S::Revoked, None)
        .await
        .unwrap());
    repo.record_denial(org.id, c.id, 3, ends - Duration::days(3))
        .await
        .unwrap();
    let get = || async {
        store
            .connections()
            .get(org.id, c.id)
            .await
            .unwrap()
            .unwrap()
    };
    night(&store, &mail, ends - Duration::hours(51)).await;
    assert_eq!(get().await.status, S::Revoked);
    night(&store, &mail, ends - Duration::hours(49)).await;
    // An organisation billing_sync run backs up the nightly's own quantity sync.
    let jobs = store.jobs();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].kind, opsagent_ledger::JobKind::BillingSync);
    let now = get().await;
    let reason = now.status_reason.as_deref();
    assert_eq!(
        (now.status, reason),
        (S::Disconnected, Some(REVOKED_REASON))
    );
    let audit = store.audit_entries();
    let e = audit
        .iter()
        .find(|e| e.action == "connection.disconnect")
        .unwrap();
    assert_eq!((e.organisation_id, e.actor), (Some(org.id), Actor::System));
    assert_eq!(e.target, Some(("connection", c.id.to_string())));
    assert_eq!(e.outcome, REVOKED_REASON);
}

#[tokio::test]
async fn past_due_7_days_pauses_and_notifies_once() {
    let (store, mail) = (MemStore::default(), Arc::new(CaptureMailer::default()));
    let (_, org) = owned_org(&store, "o@example.com", "Acme").await;
    let t0 = Utc.with_ymd_and_hms(2026, 11, 1, 0, 0, 0).unwrap();
    let s = sub(B::Active, t0 + Duration::days(20));
    store
        .apply_subscription(org.id, &s, t0 - Duration::days(1))
        .await
        .unwrap();
    assert!(store.apply_payment(org.id, B::PastDue, t0).await.unwrap());
    let status = || async { BillingRepo::billing(&store, org.id).await.unwrap().status };
    night(&store, &mail, t0 + Duration::days(6)).await;
    // The first-failure mail, not yet the paused one.
    assert_eq!((status().await, mail.sent().len()), (B::PastDue, 1));
    night(&store, &mail, t0 + Duration::days(7)).await;
    assert_eq!((status().await, mail.sent().len()), (B::Paused, 2));
    assert!(mail.sent()[1].text.contains("paused"));
    night(&store, &mail, t0 + Duration::days(8)).await;
    assert_eq!((status().await, mail.sent().len()), (B::Paused, 2));
    // Paid: active again, and no notice.
    let paid = t0 + Duration::days(9);
    assert!(store.apply_payment(org.id, B::Active, paid).await.unwrap());
    night(&store, &mail, t0 + Duration::days(10)).await;
    assert_eq!((status().await, mail.sent().len()), (B::Active, 2));
}

#[tokio::test]
async fn first_failed_payment_is_mailed_once_per_spell() {
    let (store, mail) = (MemStore::default(), Arc::new(CaptureMailer::default()));
    let (_, org) = owned_org(&store, "o@example.com", "Acme").await;
    let t0 = Utc.with_ymd_and_hms(2026, 11, 1, 0, 0, 0).unwrap();
    let s = sub(B::Active, t0 + Duration::days(20));
    store
        .apply_subscription(org.id, &s, t0 - Duration::days(1))
        .await
        .unwrap();
    night(&store, &mail, t0).await;
    assert!(mail.sent().is_empty());
    assert!(store.apply_payment(org.id, B::PastDue, t0).await.unwrap());
    for d in [0, 1, 2] {
        night(&store, &mail, t0 + Duration::days(d)).await; // later nights find it done
    }
    let m = mail.sent();
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].subject, "Your OpsAgent payment failed");
    assert!(m[0].text.contains("7 days") && m[0].text.ends_with("/settings/billing"));
    // Fixed, then failing again: a new spell, a new mail.
    let fixed = t0 + Duration::days(3);
    assert!(store.apply_payment(org.id, B::Active, fixed).await.unwrap());
    let again = t0 + Duration::days(10);
    assert!(store
        .apply_payment(org.id, B::PastDue, again)
        .await
        .unwrap());
    night(&store, &mail, again).await;
    night(&store, &mail, again + Duration::days(1)).await;
    assert_eq!(mail.sent().len(), 2);
}

#[tokio::test]
async fn trial_ended_is_mailed_once_and_only_while_recent() {
    let (store, mail) = (MemStore::default(), Arc::new(CaptureMailer::default()));
    let (_, org) = owned_org(&store, "o@example.com", "Acme").await;
    let ends = Utc.with_ymd_and_hms(2026, 11, 12, 10, 0, 0).unwrap();
    let ended = sub(B::TrialEnded, ends);
    store
        .apply_subscription(org.id, &ended, ends)
        .await
        .unwrap();
    // An old ending (before this mail existed) is not announced.
    night(&store, &mail, ends + Duration::days(30)).await;
    assert!(mail.sent().is_empty());
    for h in [2, 26, 50] {
        night(&store, &mail, ends + Duration::hours(h)).await;
    }
    let m = mail.sent();
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].subject, "Your OpsAgent trial has ended");
    assert!(m[0].text.ends_with("/settings/billing"));
}
