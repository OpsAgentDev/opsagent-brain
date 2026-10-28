//! Passkeys (WebAuthn credentials) a user signs in with. User-scoped, like `users`.
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::repo::RepoResult;

#[derive(Debug, Clone, PartialEq)]
pub struct StoredPasskey {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    /// The WebAuthn library's serialised credential; opaque here.
    pub credential: serde_json::Value,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[async_trait]
pub trait PasskeysRepo: Send + Sync {
    /// `RepoError::Conflict("passkey_exists")` if the credential id is already stored.
    async fn add(&self, p: &StoredPasskey) -> RepoResult<()>;
    /// Oldest first.
    async fn for_user(&self, user_id: Uuid) -> RepoResult<Vec<StoredPasskey>>;
    async fn by_credential_id(&self, cred_id: &[u8]) -> RepoResult<Option<StoredPasskey>>;
    /// Stores the credential's new state (its counter) and when it was used.
    async fn update_after_use(
        &self,
        id: Uuid,
        credential: &serde_json::Value,
        at: DateTime<Utc>,
    ) -> RepoResult<()>;
    /// `false` if `id` is unknown or not `user_id`'s.
    async fn remove(&self, user_id: Uuid, id: Uuid) -> RepoResult<bool>;
}
