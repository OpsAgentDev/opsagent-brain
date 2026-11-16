use std::sync::Arc;

use opsagent_core::{
    audit::AuditEntry,
    billing::{BillingProvider, BillingStatus, Tier},
};
use uuid::Uuid;

use super::{conflict, provider_failed, unavailable, BillingSettings};
use crate::{
    actions::{orgs::OrgScope, uow::UnitOfWork},
    error::{AppError, AppResult},
};

/// Moves a `trialing` or `active` subscription to a higher tier (owner only; the caller
/// checks), prorated now; a trial stays a trial. The tier is stored at once and audited; the
/// webhook that follows stays the source of truth. 409 `no_subscription` in any other status,
/// 409 `not_an_upgrade` for the same or a lower tier, 422 for an unknown tier.
pub struct ChangePlan {
    uow: Arc<dyn UnitOfWork>,
    provider: Arc<dyn BillingProvider>,
    settings: BillingSettings,
}

impl ChangePlan {
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

    pub async fn run(&self, scope: &OrgScope, tier: &str) -> AppResult<()> {
        self.settings.require_stripe()?;
        let tier = Tier::parse(tier).ok_or_else(|| AppError::Invalid("unknown tier".into()))?;
        let org = scope.organisation.id;
        let b = self.uow.billing().billing(org).await?;
        let live = matches!(b.status, BillingStatus::Trialing | BillingStatus::Active);
        let Some(sub) = b.subscription.filter(|_| live) else {
            return Err(conflict(
                "no_subscription",
                "There is no active or trial subscription to upgrade.",
            ));
        };
        if sub.tier.is_some_and(|t| tier <= t) {
            return Err(conflict(
                "not_an_upgrade",
                "Choose a higher plan; lower plans are changed in the billing portal.",
            ));
        }
        let price_id = self.settings.price(tier);
        if price_id.is_empty() {
            return Err(unavailable());
        }
        // A fresh key: a repeat sees the stored tier and is refused above, and a reused key
        // would replay an old change after a portal downgrade.
        let idem = format!("plan:{org}:{}", Uuid::new_v4());
        let changed = self
            .provider
            .change_price(&sub.subscription_id, price_id, &idem);
        changed.await.map_err(provider_failed)?;
        let tx = self.uow.begin().await?;
        tx.billing().set_tier(org, tier).await?;
        let mut entry = AuditEntry::member(Some(org), scope.member.user_id, "billing.plan", None);
        entry.meta = serde_json::json!({ "from": sub.tier.map(Tier::as_str), "to": tier.as_str() });
        tx.audit().record(entry).await?;
        tx.commit().await?;
        Ok(())
    }
}
