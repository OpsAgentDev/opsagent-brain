//! The anonymous contact form. Not tenant-scoped: the sender has no organisation.
mod send;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::user::Email;
use uuid::Uuid;

pub use send::{ContactInput, ContactOutcome, SendContact};

use crate::error::AppResult;

/// Storage port for contact messages.
#[async_trait]
pub trait ContactStore: Send + Sync {
    /// Saves a validated message (`topic` lowercase) and returns its id.
    async fn insert(
        &self,
        name: &str,
        email: &Email,
        topic: &str,
        message: &str,
    ) -> AppResult<Uuid>;
    /// Records that the mail for `id` reached the mailer at `at`.
    async fn mark_forwarded(&self, id: Uuid, at: DateTime<Utc>) -> AppResult<()>;
}

pub struct Contact {
    pub send: SendContact,
}
