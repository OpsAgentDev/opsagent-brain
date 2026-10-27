//! The pre-signup waitlist. Not tenant-scoped: there is no organisation yet.
mod join;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::user::Email;
use uuid::Uuid;

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

pub struct Waitlist {
    pub join: JoinWaitlist,
}
