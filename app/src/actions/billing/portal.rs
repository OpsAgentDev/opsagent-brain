use std::sync::Arc;

use opsagent_core::billing::BillingProvider;
use uuid::Uuid;

use super::{conflict, provider_failed, BillingSettings};
use crate::{actions::uow::UnitOfWork, error::AppResult};

/// A Stripe Customer Portal URL (owner only; the caller checks). 409 `no_customer` before the
/// first Checkout created one.
pub struct OpenPortal {
    uow: Arc<dyn UnitOfWork>,
    provider: Arc<dyn BillingProvider>,
    settings: BillingSettings,
}

impl OpenPortal {
    pub fn new(
        uow: Arc<dyn UnitOfWork>,
        provider: Arc<dyn BillingProvider>,
        settings: BillingSettings,
    ) -> Self {
        Self {
            uow,
            provider,
            settings,
        }
    }

    pub async fn run(&self, organisation_id: Uuid) -> AppResult<String> {
        self.settings.require_stripe()?;
        let b = self.uow.billing().billing(organisation_id).await?;
        let Some(customer_id) = b.customer_id else {
            return Err(conflict(
                "no_customer",
                "Start a subscription first; there is nothing to manage yet.",
            ));
        };
        let back = self.settings.return_url("portal");
        let url = self.provider.portal_session(&customer_id, &back).await;
        url.map_err(provider_failed)
    }
}
