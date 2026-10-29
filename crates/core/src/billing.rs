//! Billing (billing.md, PRD 7.9): tiers and their limits, an organisation's billing state,
//! and the ports to the payment provider and to storage.
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::repo::RepoResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Starter,
    Team,
    Scale,
}

impl Tier {
    pub const ALL: [Tier; 3] = [Self::Starter, Self::Team, Self::Scale];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Starter => "starter",
            Self::Team => "team",
            Self::Scale => "scale",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.as_str() == s)
    }

    /// The list price per billable connection per month, in US dollars (billing.md, Plans).
    pub const fn monthly_usd(self) -> u32 {
        match self {
            Self::Starter => 99,
            Self::Team => 299,
            Self::Scale => 599,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BillingStatus {
    /// Never subscribed (every organisation from before billing).
    #[default]
    None,
    Trialing,
    Active,
    PastDue,
    /// Past due for 7 days or more; set by `billing_sync`, not by Stripe.
    Paused,
    Canceled,
    /// The subscription was deleted while still trialing.
    TrialEnded,
}

impl BillingStatus {
    pub const ALL: [BillingStatus; 7] = [
        Self::None,
        Self::Trialing,
        Self::Active,
        Self::PastDue,
        Self::Paused,
        Self::Canceled,
        Self::TrialEnded,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Trialing => "trialing",
            Self::Active => "active",
            Self::PastDue => "past_due",
            Self::Paused => "paused",
            Self::Canceled => "canceled",
            Self::TrialEnded => "trial_ended",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.as_str() == s)
    }

    /// A subscription exists and is not over (paying, trialing, or behind on payment).
    pub fn is_subscribed(self) -> bool {
        matches!(
            self,
            Self::Trialing | Self::Active | Self::PastDue | Self::Paused
        )
    }
}

/// `None` is unlimited. Investigation caps are stored only; nothing enforces them yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PlanLimits {
    pub members: Option<u32>,
    pub integrations: Option<u32>,
    pub investigations: u32,
}

/// The tier table (billing.md, Global Constraints).
pub const fn plan_limits(tier: Tier) -> PlanLimits {
    match tier {
        Tier::Starter => PlanLimits {
            members: Some(2),
            integrations: Some(1),
            investigations: 60,
        },
        Tier::Team => PlanLimits {
            members: Some(5),
            integrations: None,
            investigations: 300,
        },
        Tier::Scale => PlanLimits {
            members: None,
            integrations: None,
            investigations: 1000,
        },
    }
}

/// An organisation's stored billing state; webhooks are its writers.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct OrgBilling {
    pub customer_id: Option<String>,
    pub subscription: Option<SubscriptionState>,
    pub status: BillingStatus,
    pub past_due_since: Option<DateTime<Utc>>,
}

/// A subscription as the latest applied Stripe event described it.
#[derive(Debug, Clone, PartialEq)]
pub struct SubscriptionState {
    pub subscription_id: String,
    pub status: BillingStatus,
    pub tier: Option<Tier>,
    pub quantity: i32,
    pub trial_ends_at: Option<DateTime<Utc>>,
    pub current_period_start: Option<DateTime<Utc>>,
    pub current_period_end: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BillingError {
    /// The provider has no such object (a subscription already deleted).
    #[error("not found")]
    NotFound,
    /// A stable code (`http_<status>`, `transport`, `bad_response`, or the provider's error
    /// code); never provider text.
    #[error("billing provider: {0}")]
    Other(String),
}

pub type BillingResult<T> = Result<T, BillingError>;

/// A hosted Checkout session for one subscription item, quantity 1.
#[derive(Debug, Clone)]
pub struct CheckoutRequest {
    pub organisation_id: Uuid,
    pub customer_id: String,
    pub price_id: String,
    /// Starts the 14-day trial (card still required).
    pub trial: bool,
    pub success_url: String,
    pub cancel_url: String,
}

/// The payment provider. Every write carries the caller's idempotency key `idem`.
#[async_trait]
pub trait BillingProvider: Send + Sync {
    /// Returns the new customer's id.
    async fn create_customer(
        &self,
        organisation_id: Uuid,
        name: &str,
        email: &str,
        idem: &str,
    ) -> BillingResult<String>;

    /// Returns the hosted Checkout URL.
    async fn checkout_session(&self, req: &CheckoutRequest, idem: &str) -> BillingResult<String>;

    /// Returns the hosted Customer Portal URL.
    async fn portal_session(&self, customer_id: &str, return_url: &str) -> BillingResult<String>;

    /// Sets the subscription's one item to `quantity`; `prorate` charges the difference now,
    /// otherwise it applies from the next period.
    async fn set_quantity(
        &self,
        subscription_id: &str,
        quantity: i32,
        prorate: bool,
        idem: &str,
    ) -> BillingResult<()>;

    /// Cancels immediately; `NotFound` when the provider has no such subscription.
    async fn cancel_subscription(&self, subscription_id: &str, idem: &str) -> BillingResult<()>;
}

#[async_trait]
pub trait BillingRepo: Send + Sync {
    /// `NotFound` for an unknown organisation.
    async fn billing(&self, organisation_id: Uuid) -> RepoResult<OrgBilling>;

    async fn set_customer(&self, organisation_id: Uuid, customer_id: &str) -> RepoResult<()>;

    /// Writes `s` unless an event created after `event_created` was already applied, or one
    /// from the same second with a later `current_period_end` (Stripe stamps whole seconds);
    /// `false` (writing nothing) when this one is stale. `past_due_since` is kept from the first
    /// past-due event and cleared by any other status; a `past_due` event leaves `paused` as it is.
    /// An event older than the last `apply_payment` keeps that payment's status (and
    /// `past_due_since`) and writes the rest.
    async fn apply_subscription(
        &self,
        organisation_id: Uuid,
        s: &SubscriptionState,
        event_created: DateTime<Utc>,
    ) -> RepoResult<bool>;

    /// An invoice outcome: `PastDue` from `trialing`/`active`, or `Active` from
    /// `past_due`/`paused`; any other pair, no stored subscription, or a subscription or
    /// payment event newer than `at` already applied writes nothing (`false`). Only the status
    /// and `past_due_since` change; the subscription-event order (`apply_subscription`) is kept.
    async fn apply_payment(
        &self,
        organisation_id: Uuid,
        status: BillingStatus,
        at: DateTime<Utc>,
    ) -> RepoResult<bool>;

    /// The organisation (live or deleted) whose provider customer is `customer_id`.
    async fn org_for_customer(&self, customer_id: &str) -> RepoResult<Option<Uuid>>;

    /// Records a provider event; `false` when it was already recorded.
    async fn record_event(&self, event_id: &str, event_type: &str) -> RepoResult<bool>;

    /// Live organisations whose status `is_subscribed`, for the nightly `billing_sync`.
    /// tenancy: the nightly pass; each organisation scopes its own work.
    async fn subscribed_orgs(&self) -> RepoResult<Vec<Uuid>>;

    /// `past_due` to `paused` when past due since at or before `past_due_before` (the only
    /// status `billing_sync` writes); `false` otherwise.
    async fn pause(
        &self,
        organisation_id: Uuid,
        past_due_before: DateTime<Utc>,
    ) -> RepoResult<bool>;

    /// Distinct accounts in `connected`, `degraded` or `revoked`, plus those ever connected and
    /// disconnected at or after `period_start`. The caller applies the minimum of 1 while subscribed.
    async fn billable_count(
        &self,
        organisation_id: Uuid,
        period_start: DateTime<Utc>,
    ) -> RepoResult<i64>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_limits_match_spec() {
        let row = |t| {
            let l = plan_limits(t);
            (l.members, l.integrations, l.investigations)
        };
        assert_eq!(row(Tier::Starter), (Some(2), Some(1), 60));
        assert_eq!(row(Tier::Team), (Some(5), None, 300));
        assert_eq!(row(Tier::Scale), (None, None, 1000));
    }

    #[test]
    fn names_round_trip() {
        for t in Tier::ALL {
            assert_eq!(Tier::parse(t.as_str()), Some(t));
            assert_eq!(serde_json::to_value(t).unwrap(), t.as_str());
        }
        for s in BillingStatus::ALL {
            assert_eq!(BillingStatus::parse(s.as_str()), Some(s));
            assert_eq!(serde_json::to_value(s).unwrap(), s.as_str());
        }
        assert_eq!(Tier::parse("gold"), None);
        assert_eq!(BillingStatus::parse("unpaid"), None);
    }
}
