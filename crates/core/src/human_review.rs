//! Human review requests (human-review.md): a record of who asked for a review of what, at
//! which price, and whether it is paid. The founder answers by email.
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::repo::RepoResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewKind {
    Finding,
    Account,
}

impl ReviewKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Finding => "finding",
            Self::Account => "account",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "finding" => Some(Self::Finding),
            "account" => Some(Self::Account),
            _ => None,
        }
    }
}

/// How a request is paid: `Invoice` outside the product (no Stripe), or Stripe Checkout,
/// `Pending` until its webhook marks it `Paid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Payment {
    Invoice,
    Pending,
    Paid,
}

impl Payment {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Invoice => "invoice",
            Self::Pending => "pending",
            Self::Paid => "paid",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "invoice" => Some(Self::Invoice),
            "pending" => Some(Self::Pending),
            "paid" => Some(Self::Paid),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NewReviewRequest {
    pub organisation_id: Uuid,
    pub kind: ReviewKind,
    pub finding_id: Option<Uuid>,
    pub connection_id: Option<Uuid>,
    /// The finding title or connection name when asked.
    pub target_label: String,
    pub note: Option<String>,
    /// The price when asked.
    pub price_cents: i32,
    pub requested_by: Uuid,
    pub requester_email: String,
    pub payment: Payment,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReviewRequest {
    pub id: Uuid,
    pub kind: ReviewKind,
    pub finding_id: Option<Uuid>,
    pub connection_id: Option<Uuid>,
    pub target_label: String,
    pub note: Option<String>,
    pub price_cents: i32,
    pub requested_by: Uuid,
    pub requester_email: String,
    pub payment: Payment,
    pub paid_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[async_trait]
pub trait HumanReviewsRepo: Send + Sync {
    async fn insert(&self, r: &NewReviewRequest) -> RepoResult<Uuid>;
    /// Requests of `org` created after `since`. Inside a transaction it also holds the org's
    /// request lock until commit, so a following `insert` cannot race another request.
    async fn count_since(&self, org: Uuid, since: DateTime<Utc>) -> RepoResult<u64>;
    /// Newest first.
    async fn list(&self, org: Uuid, limit: u64) -> RepoResult<Vec<ReviewRequest>>;
    /// Sets `Paid` and `paid_at = now` on `org`'s request `id` if it is `Pending`, and returns
    /// it; `None` when it is unknown, another org's, or not pending (so a replay is a no-op).
    async fn mark_paid(
        &self,
        org: Uuid,
        id: Uuid,
        now: DateTime<Utc>,
    ) -> RepoResult<Option<ReviewRequest>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payment_round_trips() {
        for p in [Payment::Invoice, Payment::Pending, Payment::Paid] {
            assert_eq!(Payment::parse(p.as_str()), Some(p));
        }
        assert_eq!(Payment::parse("free"), None);
    }
}
