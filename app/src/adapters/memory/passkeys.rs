use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    passkey::{PasskeysRepo, StoredPasskey},
    repo::{RepoError, RepoResult},
};
use uuid::Uuid;

use super::MemStore;

#[async_trait]
impl PasskeysRepo for MemStore {
    async fn add(&self, p: &StoredPasskey) -> RepoResult<()> {
        let mut s = self.state();
        if s.passkeys
            .iter()
            .any(|k| k.credential_id == p.credential_id)
        {
            return Err(RepoError::Conflict("passkey_exists"));
        }
        s.passkeys.push(p.clone());
        Ok(())
    }

    async fn for_user(&self, user_id: Uuid) -> RepoResult<Vec<StoredPasskey>> {
        let s = self.state();
        let mut found: Vec<_> = s
            .passkeys
            .iter()
            .filter(|k| k.user_id == user_id)
            .cloned()
            .collect();
        found.sort_by_key(|k| (k.created_at, k.id));
        Ok(found)
    }

    async fn by_credential_id(&self, cred_id: &[u8]) -> RepoResult<Option<StoredPasskey>> {
        let s = self.state();
        Ok(s.passkeys
            .iter()
            .find(|k| k.credential_id == cred_id)
            .cloned())
    }

    async fn update_after_use(
        &self,
        id: Uuid,
        credential: &serde_json::Value,
        at: DateTime<Utc>,
    ) -> RepoResult<()> {
        let mut s = self.state();
        let k = s
            .passkeys
            .iter_mut()
            .find(|k| k.id == id)
            .ok_or(RepoError::NotFound)?;
        k.credential = credential.clone();
        k.last_used_at = Some(at);
        Ok(())
    }

    async fn remove(&self, user_id: Uuid, id: Uuid) -> RepoResult<bool> {
        let mut s = self.state();
        let before = s.passkeys.len();
        s.passkeys.retain(|k| !(k.id == id && k.user_id == user_id));
        Ok(s.passkeys.len() < before)
    }
}
