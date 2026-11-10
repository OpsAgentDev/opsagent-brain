//! The pre-signup waitlist. Not tenant-scoped: there is no organisation yet.
mod announce;
mod join;
mod verify;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::user::Email;
use uuid::Uuid;

pub use announce::{AnnounceReport, AnnounceWaitlist, SEND_GAP};
pub use join::{JoinInput, JoinOutcome, JoinWaitlist, RESEND_AFTER_SECS};
pub use verify::VerifyWaitlist;

use crate::error::AppResult;

/// Storage port for waitlist entries.
#[async_trait]
pub trait WaitlistStore: Send + Sync {
    /// Adds `email` with an unverified link token; `Some(id)` when a confirmation mail should go:
    /// a new row, or an unverified one whose last mail went out over `RESEND_AFTER` ago (its token
    /// is replaced). `None` otherwise, so an address gets at most one mail per window
    /// (race-safe: the database decides).
    async fn insert(
        &self,
        email: &Email,
        source: Option<&str>,
        token_hash: &str,
    ) -> AppResult<Option<Uuid>>;
    /// Marks the entry holding `token_hash` verified and clears the token; `false` if none does.
    async fn verify(&self, token_hash: &str, at: DateTime<Utc>) -> AppResult<bool>;
    /// Records that the confirmation mail for `id` went out at `at`.
    async fn mark_confirmed(&self, id: Uuid, at: DateTime<Utc>) -> AppResult<()>;
}

/// Storage port for the announcement.
#[async_trait]
pub trait AnnounceStore: Send + Sync {
    /// Every verified entry not yet announced: (id, address).
    async fn unannounced(&self) -> AppResult<Vec<(Uuid, String)>>;
    /// Records that the announcement for `id` went out at `at`.
    async fn mark_announced(&self, id: Uuid, at: DateTime<Utc>) -> AppResult<()>;
}

pub struct Waitlist {
    pub join: JoinWaitlist,
    pub verify: VerifyWaitlist,
    pub announce: AnnounceWaitlist,
}
