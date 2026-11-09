//! The pre-signup waitlist. Not tenant-scoped: there is no organisation yet.
mod announce;
mod join;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::user::Email;
use uuid::Uuid;

pub use announce::{AnnounceReport, AnnounceWaitlist, SEND_GAP};
pub use join::{JoinInput, JoinOutcome, JoinWaitlist};

use crate::error::AppResult;

/// Storage port for waitlist entries.
#[async_trait]
pub trait WaitlistStore: Send + Sync {
    /// Adds `email`; `Some(id)` only when a row was newly inserted, `None` on a duplicate
    /// (race-safe: the database decides).
    async fn insert(&self, email: &Email, source: Option<&str>) -> AppResult<Option<Uuid>>;
    /// Records that the confirmation mail for `id` went out at `at`.
    async fn mark_confirmed(&self, id: Uuid, at: DateTime<Utc>) -> AppResult<()>;
}

/// Storage port for the announcement.
#[async_trait]
pub trait AnnounceStore: Send + Sync {
    /// Every entry not yet announced: (id, address).
    async fn unannounced(&self) -> AppResult<Vec<(Uuid, String)>>;
    /// Records that the announcement for `id` went out at `at`.
    async fn mark_announced(&self, id: Uuid, at: DateTime<Utc>) -> AppResult<()>;
}

pub struct Waitlist {
    pub join: JoinWaitlist,
    pub announce: AnnounceWaitlist,
}
