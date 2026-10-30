//! Billing use cases (billing.md, Build decisions 11 and 5): the organisation's billing view,
//! Stripe Checkout and Portal sessions, and the Stripe webhook, which is the only writer of
//! billing state.
mod checkout;
mod gate;
mod nightly;
mod portal;
mod skip_gated;
mod sync;
mod webhook;

use std::sync::Arc;

use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use opsagent_core::billing::{plan_limits, BillingError, BillingStatus, PlanLimits, Tier};
use uuid::Uuid;

pub(crate) use checkout::create_customer;
pub use checkout::StartCheckout;
pub use gate::{trial_limit, BillingGate, Seat, BILLING_REQUIRED, PLAN_LIMIT, TRIAL_LIMIT};
pub use portal::OpenPortal;
pub use skip_gated::SkipGatedRun;
pub use sync::{enqueue_sync, BillingSync};
pub use webhook::HandleWebhook;

use crate::{
    actions::uow::UnitOfWork,
    config::Config,
    error::{AppError, AppResult},
};

pub const BILLING_UNAVAILABLE: &str = "billing_unavailable";

pub struct Billing {
    pub get_billing: GetBilling,
    pub checkout: StartCheckout,
    pub portal: OpenPortal,
    pub webhook: HandleWebhook,
    pub sync: BillingSync,
    pub gate: BillingGate,
    pub skip_gated: SkipGatedRun,
}

/// What the billing actions read from `Config`. No `Debug`: it holds the webhook secret.
#[derive(Clone)]
pub struct BillingSettings {
    pub stripe_configured: bool,
    pub webhook_configured: bool,
    pub webhook_secret: String,
    pub price_starter: String,
    pub price_team: String,
    pub price_scale: String,
    pub web_base_url: String,
    pub enforced: bool,
}

impl BillingSettings {
    pub fn new(c: &Config) -> Self {
        Self {
            stripe_configured: c.stripe_configured(),
            webhook_configured: c.webhook_configured(),
            webhook_secret: c.stripe_webhook_secret.clone(),
            price_starter: c.stripe_price_starter.clone(),
            price_team: c.stripe_price_team.clone(),
            price_scale: c.stripe_price_scale.clone(),
            web_base_url: c.web_base_url.clone(),
            enforced: c.billing_enforced,
        }
    }

    fn price(&self, tier: Tier) -> &str {
        match tier {
            Tier::Starter => &self.price_starter,
            Tier::Team => &self.price_team,
            Tier::Scale => &self.price_scale,
        }
    }

    /// The tier a Stripe price id stands for.
    fn tier_of(&self, price_id: &str) -> Option<Tier> {
        Tier::ALL
            .into_iter()
            .find(|t| !price_id.is_empty() && self.price(*t) == price_id)
    }

    /// `WEB_BASE_URL/settings/billing?status=<status>`.
    fn return_url(&self, status: &str) -> String {
        let base = self.web_base_url.trim_end_matches('/');
        format!("{base}/settings/billing?status={status}")
    }

    fn require_stripe(&self) -> AppResult<()> {
        self.stripe_configured.then_some(()).ok_or_else(unavailable)
    }
}

/// 503 `billing_unavailable`: Stripe is not configured.
pub(crate) fn unavailable() -> AppError {
    AppError::Refused {
        status: StatusCode::SERVICE_UNAVAILABLE,
        code: BILLING_UNAVAILABLE,
        detail: "Billing is not available.".into(),
    }
}

/// 502 `billing_unavailable`: a Stripe call failed. Only the stable code is logged.
pub(crate) fn provider_failed(e: BillingError) -> AppError {
    tracing::warn!(error = %e, "stripe call failed");
    AppError::Refused {
        status: StatusCode::BAD_GATEWAY,
        code: BILLING_UNAVAILABLE,
        detail: "The billing provider could not be reached; try again.".into(),
    }
}

fn conflict(code: &'static str, detail: &str) -> AppError {
    AppError::Refused {
        status: StatusCode::CONFLICT,
        code,
        detail: detail.into(),
    }
}

/// An organisation's billing as `GET /orgs/{org}/billing` reports it.
#[derive(Debug, Clone, PartialEq)]
pub struct BillingView {
    pub status: BillingStatus,
    pub tier: Option<Tier>,
    pub trial_ends_at: Option<DateTime<Utc>>,
    pub current_period_end: Option<DateTime<Utc>>,
    /// Connections billed: at least 1 while subscribed, 0 otherwise.
    pub quantity: i32,
    pub limits: Option<PlanLimits>,
    /// More members or active integrations than the tier allows.
    pub over_limit: bool,
    /// `BILLING_ENFORCED`.
    pub enforced: bool,
}

pub struct GetBilling {
    uow: Arc<dyn UnitOfWork>,
    settings: BillingSettings,
}

impl GetBilling {
    pub fn new(uow: Arc<dyn UnitOfWork>, settings: BillingSettings) -> Self {
        Self { uow, settings }
    }

    pub async fn run(&self, organisation_id: Uuid) -> AppResult<BillingView> {
        self.settings.require_stripe()?;
        let b = self.uow.billing().billing(organisation_id).await?;
        let sub = b.subscription.as_ref();
        let tier = sub.and_then(|s| s.tier);
        let limits = tier.map(plan_limits);
        let quantity = match b.status.is_subscribed() {
            true => sub.map_or(1, |s| s.quantity.max(1)),
            false => 0,
        };
        let over_limit = match limits {
            Some(l) => gate::Usage::of(&*self.uow, organisation_id).await?.over(l),
            None => false,
        };
        Ok(BillingView {
            status: b.status,
            tier,
            trial_ends_at: sub.and_then(|s| s.trial_ends_at),
            current_period_end: sub.and_then(|s| s.current_period_end),
            quantity,
            limits,
            over_limit,
            enforced: self.settings.enforced,
        })
    }
}
