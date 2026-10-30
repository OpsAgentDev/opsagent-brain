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

    /// Scans, deliveries and writes run (billing.md, Gating): trialing, active, or past due
    /// under 7 days (`billing_sync` moves 7 days or more to `paused`).
    pub fn in_good_standing(self) -> bool {
        matches!(self, Self::Trialing | Self::Active | Self::PastDue)
    }
}

/// `None` is unlimited. `ai_credits`: Dashboard AI credits per account paid for, per period.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PlanLimits {
    pub members: Option<u32>,
    pub integrations: Option<u32>,
    pub ai_credits: u32,
}

/// The tier table (billing.md, Global Constraints).
pub const fn plan_limits(tier: Tier) -> PlanLimits {
    match tier {
        Tier::Starter => PlanLimits {
            members: Some(2),
            integrations: Some(1),
            ai_credits: 1000,
        },
        Tier::Team => PlanLimits {
            members: Some(5),
            integrations: None,
            ai_credits: 5000,
        },
        Tier::Scale => PlanLimits {
            members: None,
            integrations: None,
            ai_credits: 15000,
        },
    }
}

/// Past due this many days or more is `paused` (`billing_sync` writes it nightly; the gate
/// reads it from `past_due_since` before then).
pub const PAUSE_AFTER_DAYS: i64 = 7;

/// An organisation's stored billing state; webhooks are its writers.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct OrgBilling {
    pub customer_id: Option<String>,
    pub subscription: Option<SubscriptionState>,
    pub status: BillingStatus,
    pub past_due_since: Option<DateTime<Utc>>,
    /// The highest quantity paid for in the current period (reset to the subscription's
    /// quantity when a new period starts); an increase up to it is not charged again.
    pub paid_quantity: Option<i32>,
}

impl OrgBilling {
    /// `BillingStatus::in_good_standing` at `now`, except a `past_due` that started
    /// `PAUSE_AFTER_DAYS` or more ago (the nightly has not paused it yet).
    pub fn in_good_standing(&self, now: DateTime<Utc>) -> bool {
        let cutoff = now - chrono::Duration::days(PAUSE_AFTER_DAYS);
        let overdue = self.status == BillingStatus::PastDue
            && self.past_due_since.is_some_and(|t| t <= cutoff);
        self.status.in_good_standing() && !overdue
    }
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

/// The `status_reason` of a connection `billing_sync` disconnected because it was still
/// revoked as its period was about to end; it is not billed for the next period.
pub const REVOKED_AT_PERIOD_END: &str = "revoked_at_period_end";

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

    /// Returns the hosted Checkout URL for one AI top-up (1,000 credits for US$15, one-time
    /// payment, `metadata[purpose]=ai_topup`).
    async fn topup_session(
        &self,
        customer_id: &str,
        organisation_id: Uuid,
        success_url: &str,
        cancel_url: &str,
        idem: &str,
    ) -> BillingResult<String>;

    /// Returns the hosted Customer Portal URL.
    async fn portal_session(&self, customer_id: &str, return_url: &str) -> BillingResult<String>;

    /// Sets the subscription's one item to `quantity`; `prorate` charges the difference now,
    /// otherwise nothing is charged or credited now and the next renewal bills `quantity`.
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
    /// `false` (writing nothing) when this one is stale. A new `current_period_start` (or none
    /// stored) resets `paid_quantity` to `s.quantity`. `past_due_since` is kept from the first
    /// past-due event and cleared by any other status; a `past_due` event leaves `paused` as it is.
    /// An event older than the last `apply_payment` keeps that payment's status (and
    /// `past_due_since`) and writes the rest, unless it ends the subscription (`canceled`,
    /// `trial_ended`, `none`), which always wins.
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

    /// Serialises the organisation's seat checks (trial connection, member limit) until the
    /// transaction ends. Not a row lock: FK inserts referencing the organisation (runs) are not
    /// blocked, so it cannot deadlock with them. A no-op outside a transaction.
    async fn lock_seats(&self, organisation_id: Uuid) -> RepoResult<()>;

    /// Serialises the organisation's quantity syncs until the transaction ends (a lock apart
    /// from `lock_seats`). A no-op outside a transaction.
    async fn lock_quantity(&self, organisation_id: Uuid) -> RepoResult<()>;

    /// Distinct accounts (`provider:account`) in `connected`, `degraded` or `revoked`, plus,
    /// with `since`, those ever connected and disconnected at or after it (except with reason
    /// `REVOKED_AT_PERIOD_END`): the accounts paid for this period.
    async fn billable_accounts(
        &self,
        organisation_id: Uuid,
        since: Option<DateTime<Utc>>,
    ) -> RepoResult<Vec<String>>;

    /// Records a quantity `billing_sync` set at the provider; `paid_quantity` only rises (to
    /// `paid`), so a late record never lowers what the period paid for.
    async fn record_quantity(
        &self,
        organisation_id: Uuid,
        quantity: i32,
        paid: i32,
    ) -> RepoResult<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_limits_match_spec() {
        let row = |t| {
            let l = plan_limits(t);
            (l.members, l.integrations, l.ai_credits)
        };
        assert_eq!(row(Tier::Starter), (Some(2), Some(1), 1000));
        assert_eq!(row(Tier::Team), (Some(5), None, 5000));
        assert_eq!(row(Tier::Scale), (None, None, 15000));
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

    #[test]
    fn good_standing_is_trialing_active_or_past_due() {
        let good: Vec<_> = BillingStatus::ALL
            .into_iter()
            .filter(|s| s.in_good_standing())
            .collect();
        use BillingStatus as B;
        assert_eq!(good, [B::Trialing, B::Active, B::PastDue]);
    }

    #[test]
    fn past_due_7_days_is_not_good_standing() {
        let now = Utc::now();
        let since = |d: chrono::Duration| OrgBilling {
            status: BillingStatus::PastDue,
            past_due_since: Some(now - d),
            ..Default::default()
        };
        let day = chrono::Duration::days(1);
        assert!(since(day * 7 - chrono::Duration::seconds(1)).in_good_standing(now));
        assert!(!since(day * 7).in_good_standing(now));
        let active = OrgBilling {
            status: BillingStatus::Active,
            past_due_since: Some(now - day * 30),
            ..Default::default()
        };
        assert!(active.in_good_standing(now));
    }
}
