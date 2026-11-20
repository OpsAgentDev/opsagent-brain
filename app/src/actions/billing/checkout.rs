use std::sync::Arc;

use super::{conflict, provider_failed, unavailable, BillingSettings};
use crate::{
    actions::{orgs::OrgScope, uow::UnitOfWork},
    error::{AppError, AppResult},
};
use opsagent_core::{
    billing::{BillingProvider, BillingStatus, CheckoutRequest, Tier},
    repo::Clock,
};

/// A Stripe Checkout URL for the organisation (owner only; the caller checks). The Stripe
/// customer is created on first use. An organisation that never subscribed gets the 14-day
/// trial on `team` unless its creator already started one on another organisation; one
/// whose trial ended or subscription was canceled buys `tier` outright.
/// 409 `already_subscribed` while a subscription is live (the Portal changes it).
pub struct StartCheckout {
    uow: Arc<dyn UnitOfWork>,
    provider: Arc<dyn BillingProvider>,
    clock: Arc<dyn Clock>,
    settings: BillingSettings,
}

impl StartCheckout {
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

    pub async fn run(&self, scope: &OrgScope, tier: Option<&str>) -> AppResult<String> {
        self.settings.require_stripe()?;
        let tier = match tier {
            None => Tier::Team,
            Some(t) => Tier::parse(t).ok_or_else(|| AppError::Invalid("unknown tier".into()))?,
        };
        let org = &scope.organisation;
        let b = self.uow.billing().billing(org.id).await?;
        if b.status.is_subscribed() {
            return Err(conflict(
                "already_subscribed",
                "The organisation already has a subscription; manage it in the billing portal.",
            ));
        }
        let price_id = self.settings.price(tier).to_owned();
        if price_id.is_empty() {
            return Err(unavailable());
        }
        let customer_id = match b.customer_id {
            Some(c) => c,
            None => create_customer(&*self.uow, &*self.provider, scope).await?,
        };
        // shortcut: only the webhook records a trial, so two first checkouts open at once can both start one; reserve the trial here if that is abused.
        let trial = b.status == BillingStatus::None
            && tier == Tier::Team
            && !self
                .uow
                .billing()
                .creator_used_trial_elsewhere(org.id)
                .await?;
        // One session per organisation, plan and half hour: a second tab gets the same session,
        // and Stripe completes a session once, so two tabs cannot both pay.
        let idem = format!(
            "checkout:{}:{price_id}:{trial}:{}",
            org.id,
            self.clock.now().timestamp() / 1800
        );
        let req = CheckoutRequest {
            organisation_id: org.id,
            customer_id,
            price_id,
            trial,
            success_url: self.settings.return_url(&org.slug, "success"),
            cancel_url: self.settings.return_url(&org.slug, "canceled"),
        };
        let url = self.provider.checkout_session(&req, &idem).await;
        url.map_err(provider_failed)
    }
}

/// The organisation's new Stripe customer, saved; keyed on the organisation, so a retry
/// after a failed save reuses the same customer. Also the AI top-up's.
pub(crate) async fn create_customer(
    uow: &dyn UnitOfWork,
    provider: &dyn BillingProvider,
    scope: &OrgScope,
) -> AppResult<String> {
    let org = &scope.organisation;
    let email = scope.member.email.as_str();
    let idem = format!("customer:{}", org.id);
    let made = provider.create_customer(org.id, &org.name, email, &idem);
    let id = made.await.map_err(provider_failed)?;
    uow.billing().set_customer(org.id, &id).await?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use chrono::Utc;
    use opsagent_core::billing::{BillingRepo, BillingResult, ReviewCheckout, SubscriptionState};
    use uuid::Uuid;

    use super::*;
    use crate::{
        actions::{
            billing::nightly::tests::settings,
            orgs::test_support::{owned_org, scope},
        },
        adapters::memory::{FixedClock, MemStore},
    };

    /// Records each Checkout session asked for.
    #[derive(Default)]
    struct Sessions(Mutex<Vec<CheckoutRequest>>);

    #[async_trait]
    impl BillingProvider for Sessions {
        async fn create_customer(
            &self,
            _: Uuid,
            _: &str,
            _: &str,
            _: &str,
        ) -> BillingResult<String> {
            Ok("cus_1".into())
        }
        async fn checkout_session(&self, r: &CheckoutRequest, _: &str) -> BillingResult<String> {
            self.0.lock().unwrap().push(r.clone());
            Ok("https://checkout.test/s".into())
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
        async fn topup_of_payment(&self, _: &str) -> BillingResult<Option<String>> {
            unreachable!()
        }
        async fn set_quantity(&self, _: &str, _: i32, _: bool, _: &str) -> BillingResult<()> {
            unreachable!()
        }
        async fn change_price(&self, _: &str, _: &str, _: &str) -> BillingResult<()> {
            unreachable!()
        }
        async fn cancel_subscription(&self, _: &str, _: &str) -> BillingResult<()> {
            unreachable!()
        }
    }

    fn start(store: &MemStore, stripe: &Arc<Sessions>) -> StartCheckout {
        StartCheckout::new(
            Arc::new(store.clone()),
            stripe.clone(),
            Arc::new(FixedClock(Utc::now())),
            settings(),
        )
    }

    #[tokio::test]
    async fn the_tier_picks_the_price_and_only_team_gets_the_trial() {
        let (store, stripe) = (MemStore::default(), Arc::new(Sessions::default()));
        let (owner, org) = owned_org(&store, "o@example.com", "Acme").await;
        let sc = scope(&store, &org, &owner).await;
        let checkout = start(&store, &stripe);
        for tier in [None, Some("team"), Some("starter"), Some("scale")] {
            let url = checkout.run(&sc, tier).await.unwrap();
            assert_eq!(url, "https://checkout.test/s");
        }
        let asked: Vec<_> = (stripe.0.lock().unwrap().iter())
            .map(|r| (r.price_id.clone(), r.trial))
            .collect();
        let want = [("p_t", true), ("p_t", true), ("p_s", false), ("p_x", false)];
        assert_eq!(asked, want.map(|(p, t)| (p.to_owned(), t)));

        let bad = checkout.run(&sc, Some("gold")).await.unwrap_err();
        assert!(matches!(bad, AppError::Invalid(_)), "{bad:?}");
        assert_eq!(stripe.0.lock().unwrap().len(), 4);
    }

    #[tokio::test]
    async fn team_gets_no_second_trial_from_the_same_creator() {
        let (store, stripe) = (MemStore::default(), Arc::new(Sessions::default()));
        let (owner, first) = owned_org(&store, "o@example.com", "Acme").await;
        let now = Utc::now();
        let trialed = SubscriptionState {
            subscription_id: "sub_1".into(),
            status: BillingStatus::Trialing,
            tier: Some(Tier::Team),
            quantity: 1,
            trial_ends_at: Some(now),
            current_period_start: None,
            current_period_end: None,
            cancel_at_period_end: false,
        };
        let applied = store.apply_subscription(first.id, &trialed, now);
        applied.await.unwrap();
        let (_, second) = owned_org(&store, "o@example.com", "Other").await;
        let sc = scope(&store, &second, &owner).await;
        start(&store, &stripe).run(&sc, None).await.unwrap();
        let asked = stripe.0.lock().unwrap();
        assert_eq!((asked[0].price_id.as_str(), asked[0].trial), ("p_t", false));
    }
}
