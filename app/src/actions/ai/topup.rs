use std::sync::Arc;

use opsagent_core::billing::BillingProvider;
use uuid::Uuid;

use super::AiAccess;
use crate::{
    actions::{
        billing::{create_customer, provider_failed, unavailable},
        orgs::OrgScope,
    },
    error::AppResult,
};

/// A Stripe Checkout URL for one top-up of 1,000 credits (owner only; the caller checks).
/// 503 `billing_unavailable` while Stripe or OpsAgent's key is not configured. The Stripe customer is created
/// on first use, as for a subscription; the webhook grants the credits.
pub struct StartTopup {
    access: Arc<AiAccess>,
    provider: Arc<dyn BillingProvider>,
}

impl StartTopup {
    pub fn new(access: Arc<AiAccess>, provider: Arc<dyn BillingProvider>) -> Self {
        Self { access, provider }
    }

    pub async fn run(&self, scope: &OrgScope) -> AppResult<String> {
        let s = &self.access.s;
        if !s.topups {
            return Err(unavailable());
        }
        let uow = &*self.access.uow;
        let org = scope.organisation.id;
        let customer = match uow.billing().billing(org).await?.customer_id {
            Some(c) => c,
            None => create_customer(uow, &*self.provider, scope).await?,
        };
        let (ok, cancel) = (
            s.settings_url("?topup=success"),
            s.settings_url("?topup=canceled"),
        );
        // A fresh key: each click is its own session.
        let idem = format!("topup:{}", Uuid::new_v4());
        let url = self
            .provider
            .topup_session(&customer, org, &ok, &cancel, &idem)
            .await;
        url.map_err(provider_failed)
    }
}
