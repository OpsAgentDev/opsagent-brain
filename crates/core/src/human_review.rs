//! Human review requests (human-review.md): a record of who asked for a review of what, at
//! which price. There is no status; the founder answers by email.
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
}
