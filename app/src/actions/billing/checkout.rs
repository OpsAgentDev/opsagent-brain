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
            success_url: self.settings.return_url("success"),
            cancel_url: self.settings.return_url("canceled"),
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
