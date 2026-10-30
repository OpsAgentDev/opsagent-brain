//! Dashboard AI (dashboard-ai.md): who pays, the quota, the evidence hash and the storage port.
use async_trait::async_trait;
use chrono::{DateTime, Datelike, TimeZone, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    billing::{plan_limits, BillingStatus, OrgBilling, Tier},
    model::{AiProvider, Usage},
    repo::RepoResult,
};

macro_rules! named {
    ($t:ident { $($v:ident => $s:literal),* $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $t { $($v),* }

        impl $t {
            pub const ALL: &'static [$t] = &[$(Self::$v),*];

            pub fn as_str(self) -> &'static str {
                match self { $(Self::$v => $s),* }
            }

            pub fn parse(s: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|v| v.as_str() == s)
            }
        }
    };
}

named!(KeySource { OpsAgent => "opsagent", Byok => "byok" });
named!(KeyStatus { Ok => "ok", Failing => "failing", ProviderOutage => "provider_outage" });
named!(Purpose { Explain => "explain", Chat => "chat" });
named!(ModelRole { Routine => "routine", Chat => "chat" });

/// The model a BYOK key uses for each role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleModels {
    pub routine: String,
    pub chat: String,
}

/// An organisation's own provider key (BYOK), sealed like connection credentials.
#[derive(Debug, Clone, PartialEq)]
pub struct ModelKey {
    pub id: Uuid,
    pub organisation_id: Uuid,
    pub provider: AiProvider,
    pub last4: String,
    pub status: KeyStatus,
    pub status_since: DateTime<Utc>,
    pub models: RoleModels,
    /// Credits per calendar month (UTC); `None` is no ceiling.
    pub monthly_credit_ceiling: Option<Decimal>,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub kek_version: i32,
}

/// A key to store; the organisation is `AiRepo::put_key`'s argument.
#[derive(Debug, Clone, PartialEq)]
pub struct NewModelKey {
    pub provider: AiProvider,
    pub last4: String,
    pub models: RoleModels,
    pub monthly_credit_ceiling: Option<Decimal>,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub kek_version: i32,
}

/// One model call, metered.
#[derive(Debug, Clone, PartialEq)]
pub struct UsageRow {
    pub organisation_id: Uuid,
    pub member_id: Option<Uuid>,
    pub purpose: Purpose,
    pub provider: AiProvider,
    pub model: String,
    pub key_source: KeySource,
    pub usage: Usage,
    pub credits: Decimal,
    /// Priced at the role's default model (the model had no price).
    pub estimated: bool,
}

/// A cached explanation, shared by every finding of the check with the same evidence hash.
#[derive(Debug, Clone, PartialEq)]
pub struct Explanation {
    pub check_id: String,
    pub evidence_hash: String,
    pub provider: AiProvider,
    pub model: String,
    pub text: String,
    pub created_at: DateTime<Utc>,
}

/// Credits for a trial and for alpha organisations with no subscription.
const BASE_QUOTA: u32 = 1000;

/// Credits on OpsAgent's key per period (Global Constraints, Quota): the tier's credits per
/// account paid for while `active` or `past_due`; 1,000 while `trialing` (whatever the tier);
/// any other status gets 1,000 while billing is not enforced (alpha) and 0 once it is.
pub fn period_quota(b: &OrgBilling, enforced: bool) -> u32 {
    match b.status {
        BillingStatus::Trialing => BASE_QUOTA,
        BillingStatus::Active | BillingStatus::PastDue => {
            let tier = b.subscription.as_ref().and_then(|s| s.tier);
            let per_account = plan_limits(tier.unwrap_or(Tier::Starter)).ai_credits;
            per_account * b.paid_quantity.unwrap_or(1).max(1) as u32
        }
        _ if !enforced => BASE_QUOTA,
        _ => 0,
    }
}

/// The subscription's current period while it holds `now`, else the calendar month in UTC
/// holding `now` (a stale window, after a cancel or a late renewal webhook, never counts).
pub fn quota_period(b: &OrgBilling, now: DateTime<Utc>) -> (DateTime<Utc>, DateTime<Utc>) {
    let sub = b.subscription.as_ref();
    if let Some((Some(start), Some(end))) =
        sub.map(|s| (s.current_period_start, s.current_period_end))
    {
        if start <= now && now < end {
            return (start, end);
        }
    }
    let month = |y: i32, m: u32| Utc.with_ymd_and_hms(y, m, 1, 0, 0, 0).single();
    let (y, m) = (now.year(), now.month());
    let next = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
    let start = month(y, m).expect("first of the month is valid");
    let end = month(next.0, next.1).expect("first of the month is valid");
    (start, end)
}

/// `text` with the resource's identity, and its name (the identity's last segment after `:`
/// or `/`, when 3 characters or more), replaced by `<resource>` (plan ruling 9).
pub fn strip_identity(text: &str, identity: &str) -> String {
    const MARK: &str = "<resource>";
    if identity.is_empty() {
        return text.to_owned();
    }
    let name = identity.rsplit([':', '/']).next().unwrap_or_default();
    let long = name.chars().count() >= 3;
    // Name replaced between the identity's occurrences, so it never rewrites a mark.
    text.split(identity)
        .map(|piece| match long {
            true => piece.replace(name, MARK),
            false => piece.to_owned(),
        })
        .collect::<Vec<_>>()
        .join(MARK)
}

/// Hex SHA-256 of canonical JSON `{"check_id","excerpts","variant"}` (keys sorted), the
/// excerpts stripped of the identity and sorted: equal for every resource with the same evidence.
pub fn evidence_hash(check_id: &str, variant: &str, identity: &str, excerpts: &[String]) -> String {
    #[derive(Serialize)]
    struct Canonical<'a> {
        check_id: &'a str,
        excerpts: Vec<String>,
        variant: &'a str,
    }
    let mut excerpts: Vec<String> = excerpts
        .iter()
        .map(|e| strip_identity(e, identity))
        .collect();
    excerpts.sort();
    let json = serde_json::to_vec(&Canonical {
        check_id,
        excerpts,
        variant,
    })
    .expect("strings serialise");
    Sha256::digest(json)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[async_trait]
pub trait AiRepo: Send + Sync {
    /// `NotFound` for an unknown organisation.
    async fn enabled(&self, organisation_id: Uuid) -> RepoResult<bool>;
    /// `NotFound` for an unknown organisation.
    async fn set_enabled(&self, organisation_id: Uuid, on: bool) -> RepoResult<()>;

    async fn key(&self, organisation_id: Uuid) -> RepoResult<Option<ModelKey>>;
    /// Replaces the organisation's key (a new id), with status `ok` from now.
    async fn put_key(&self, organisation_id: Uuid, k: &NewModelKey) -> RepoResult<ModelKey>;
    /// `false` when the organisation has no key.
    async fn update_key(
        &self,
        organisation_id: Uuid,
        models: &RoleModels,
        ceiling: Option<Decimal>,
    ) -> RepoResult<bool>;
    async fn delete_key(&self, organisation_id: Uuid) -> RepoResult<bool>;
    /// `true` only when the status changed (then `status_since = at`); `false` for another
    /// status-quo, an unknown key or a replaced one.
    async fn set_key_status(
        &self,
        organisation_id: Uuid,
        key_id: Uuid,
        status: KeyStatus,
        at: DateTime<Utc>,
    ) -> RepoResult<bool>;

    /// Inserts the row and takes `topup_debit` off the top-up balance (never below 0), in one
    /// transaction.
    async fn record_usage(&self, row: &UsageRow, topup_debit: Decimal) -> RepoResult<()>;
    /// Credits of `source` recorded in `since..until`.
    async fn credits_used(
        &self,
        organisation_id: Uuid,
        source: KeySource,
        since: DateTime<Utc>,
        until: DateTime<Utc>,
    ) -> RepoResult<Decimal>;
    async fn topup_balance(&self, organisation_id: Uuid) -> RepoResult<Decimal>;
    /// Records the grant and adds `credits` to the balance; `false` (nothing added) when the
    /// Stripe event was already granted.
    async fn grant_topup(
        &self,
        organisation_id: Uuid,
        credits: Decimal,
        stripe_event_id: &str,
    ) -> RepoResult<bool>;

    async fn explanation(
        &self,
        organisation_id: Uuid,
        check_id: &str,
        hash: &str,
    ) -> RepoResult<Option<Explanation>>;
    /// Stores `e` unless one exists for its check and hash; returns the stored one.
    async fn put_explanation(
        &self,
        organisation_id: Uuid,
        e: &Explanation,
    ) -> RepoResult<Explanation>;

    /// `true` the first time `key` is noted for the organisation.
    async fn notice_once(&self, organisation_id: Uuid, key: &str) -> RepoResult<bool>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::SubscriptionState;

    fn billing(status: BillingStatus, tier: Option<Tier>, paid: Option<i32>) -> OrgBilling {
        OrgBilling {
            subscription: tier.map(|t| SubscriptionState {
                subscription_id: "sub_1".into(),
                status,
                tier: Some(t),
                quantity: paid.unwrap_or(1),
                trial_ends_at: None,
                current_period_start: None,
                current_period_end: None,
            }),
            status,
            paid_quantity: paid,
            ..Default::default()
        }
    }

    #[test]
    fn period_quota_by_billing_state() {
        use BillingStatus as B;
        let q = |s, t, p, enforced| period_quota(&billing(s, t, p), enforced);
        assert_eq!(q(B::Trialing, Some(Tier::Scale), Some(3), true), 1000);
        assert_eq!(q(B::Active, Some(Tier::Starter), Some(1), true), 1000);
        assert_eq!(q(B::Active, Some(Tier::Team), Some(1), true), 5000);
        assert_eq!(q(B::Active, Some(Tier::Team), Some(3), true), 15000);
        assert_eq!(q(B::Active, Some(Tier::Scale), Some(0), true), 15000);
        assert_eq!(q(B::PastDue, Some(Tier::Team), Some(2), true), 10000);
        for s in [B::Paused, B::Canceled, B::TrialEnded] {
            assert_eq!(q(s, Some(Tier::Team), Some(1), true), 0, "{s:?}");
            assert_eq!(q(s, Some(Tier::Team), Some(1), false), 1000, "{s:?}");
        }
        assert_eq!(q(B::None, None, None, true), 0);
        assert_eq!(q(B::None, None, None, false), 1000);
    }

    #[test]
    fn quota_period_falls_back_to_utc_month() {
        let at = |s: &str| s.parse::<DateTime<Utc>>().unwrap();
        let none = OrgBilling::default();
        let now = at("2026-12-31T23:59:59Z");
        assert_eq!(
            quota_period(&none, now),
            (at("2026-12-01T00:00:00Z"), at("2027-01-01T00:00:00Z"))
        );
        let mut b = billing(BillingStatus::Active, Some(Tier::Team), Some(1));
        assert_eq!(
            quota_period(&b, at("2026-10-15T00:00:00Z")),
            (at("2026-10-01T00:00:00Z"), at("2026-11-01T00:00:00Z"))
        );
        let s = b.subscription.as_mut().unwrap();
        s.current_period_start = Some(at("2026-10-12T08:00:00Z"));
        s.current_period_end = Some(at("2026-11-12T08:00:00Z"));
        let mid = at("2026-10-20T00:00:00Z");
        assert_eq!(
            quota_period(&b, mid),
            (at("2026-10-12T08:00:00Z"), at("2026-11-12T08:00:00Z"))
        );
        // At the end instant the window is over: the calendar month.
        assert_eq!(
            quota_period(&b, at("2026-11-12T08:00:00Z")),
            (at("2026-11-01T00:00:00Z"), at("2026-12-01T00:00:00Z"))
        );
    }

    #[test]
    fn quota_period_ignores_stale_subscription_window() {
        let at = |s: &str| s.parse::<DateTime<Utc>>().unwrap();
        let mut b = billing(BillingStatus::Canceled, Some(Tier::Team), Some(1));
        let s = b.subscription.as_mut().unwrap();
        s.current_period_start = Some(at("2026-08-12T08:00:00Z"));
        s.current_period_end = Some(at("2026-09-12T08:00:00Z"));
        let now = at("2026-12-31T23:59:59Z");
        assert_eq!(
            quota_period(&b, now),
            (at("2026-12-01T00:00:00Z"), at("2027-01-01T00:00:00Z"))
        );
        // A window that starts after `now` (clock skew) is not used either.
        assert_eq!(
            quota_period(&b, at("2026-08-01T00:00:00Z")),
            (at("2026-08-01T00:00:00Z"), at("2026-09-01T00:00:00Z"))
        );
    }

    fn bucket_excerpts(name: &str) -> Vec<String> {
        vec![
            format!("{{\"Bucket\":\"arn:aws:s3:::{name}\",\"PublicAccessBlock\":false}}"),
            format!("bucket {name} grants READ to AllUsers"),
        ]
    }

    #[test]
    fn evidence_hash_same_for_two_resources() {
        let hash = |name: &str| {
            let identity = format!("arn:aws:s3:::{name}");
            evidence_hash("s3_public", "", &identity, &bucket_excerpts(name))
        };
        assert_eq!(hash("alpha"), hash("beta"));
        assert_eq!(hash("alpha").len(), 64);
        assert!(hash("alpha").chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(
            strip_identity("bucket alpha (arn:aws:s3:::alpha)", "arn:aws:s3:::alpha"),
            "bucket <resource> (<resource>)"
        );
        // A name under 3 characters is left alone.
        assert_eq!(strip_identity("ab at x/ab", "x/ab"), "ab at <resource>");
    }

    #[test]
    fn evidence_hash_changes_with_evidence() {
        let id = "arn:aws:s3:::alpha";
        let base = evidence_hash("s3_public", "", id, &bucket_excerpts("alpha"));
        let mut other = bucket_excerpts("alpha");
        other[1] = "bucket alpha grants WRITE to AllUsers".into();
        assert_ne!(base, evidence_hash("s3_public", "", id, &other));
        let excerpts = bucket_excerpts("alpha");
        assert_ne!(base, evidence_hash("s3_acl", "", id, &excerpts));
        assert_ne!(base, evidence_hash("s3_public", "acl", id, &excerpts));
        assert_ne!(base, evidence_hash("s3_public", "", id, &[]));
    }

    #[test]
    fn evidence_hash_ignores_excerpt_order() {
        let id = "arn:aws:s3:::alpha";
        let mut excerpts = bucket_excerpts("alpha");
        let a = evidence_hash("s3_public", "", id, &excerpts);
        excerpts.reverse();
        assert_eq!(a, evidence_hash("s3_public", "", id, &excerpts));
    }

    #[test]
    fn names_round_trip() {
        for s in KeySource::ALL {
            assert_eq!(KeySource::parse(s.as_str()), Some(*s));
        }
        for s in KeyStatus::ALL {
            assert_eq!(KeyStatus::parse(s.as_str()), Some(*s));
        }
        for s in Purpose::ALL {
            assert_eq!(Purpose::parse(s.as_str()), Some(*s));
        }
        for s in ModelRole::ALL {
            assert_eq!(ModelRole::parse(s.as_str()), Some(*s));
        }
        assert_eq!(KeyStatus::parse("broken"), None);
    }
}
