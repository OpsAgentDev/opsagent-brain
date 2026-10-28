//! Adding, listing and removing a user's passkeys. Ceremony state stays with the caller.
use std::sync::Arc;

use opsagent_core::{audit::AuditEntry, passkey::StoredPasskey, repo::Clock};
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, PasskeyRegistration, RegisterPublicKeyCredential, Webauthn,
};
use webauthn_rs_proto::ResidentKeyRequirement;

use crate::{
    actions::uow::UnitOfWork,
    error::{AppError, AppResult},
};

const NAME_MAX: usize = 100;

pub struct Passkeys {
    uow: Arc<dyn UnitOfWork>,
    webauthn: Arc<Webauthn>,
    clock: Arc<dyn Clock>,
}

impl Passkeys {
    pub fn new(uow: Arc<dyn UnitOfWork>, webauthn: Arc<Webauthn>, clock: Arc<dyn Clock>) -> Self {
        Self {
            uow,
            webauthn,
            clock,
        }
    }

    /// Creation options for a discoverable credential (resident key required), excluding the
    /// user's existing ones, and the state `finish_register` needs.
    pub async fn start_register(
        &self,
        user_id: Uuid,
    ) -> AppResult<(CreationChallengeResponse, PasskeyRegistration)> {
        let user = self
            .uow
            .users()
            .get(user_id)
            .await?
            .ok_or(AppError::Unauthenticated)?;
        let existing = self.uow.passkeys().for_user(user_id).await?;
        let exclude = existing
            .into_iter()
            .map(|p| p.credential_id.into())
            .collect();
        let email = user.email.as_str();
        let (mut ccr, state) = self
            .webauthn
            .start_passkey_registration(user_id, email, email, Some(exclude))
            .map_err(|e| AppError::Internal(format!("passkey registration: {e}")))?;
        if let Some(sel) = ccr.public_key.authenticator_selection.as_mut() {
            sel.resident_key = Some(ResidentKeyRequirement::Required);
            sel.require_resident_key = true;
        }
        Ok((ccr, state))
    }

    /// Verifies the authenticator's response against `state` and stores the passkey under
    /// `name` (else "Passkey <date>").
    pub async fn finish_register(
        &self,
        user_id: Uuid,
        credential: &RegisterPublicKeyCredential,
        state: PasskeyRegistration,
        name: Option<String>,
    ) -> AppResult<StoredPasskey> {
        let now = self.clock.now();
        let name = match name.as_deref().map(str::trim).filter(|n| !n.is_empty()) {
            Some(n) if n.chars().count() > NAME_MAX => {
                return Err(AppError::Invalid(format!(
                    "name must be at most {NAME_MAX} characters"
                )))
            }
            Some(n) => n.to_owned(),
            None => format!("Passkey {}", now.format("%Y-%m-%d")),
        };
        let passkey = self
            .webauthn
            .finish_passkey_registration(credential, &state)
            .map_err(|e| {
                tracing::info!(error = %e, "passkey registration rejected");
                AppError::Invalid("The passkey could not be verified.".into())
            })?;
        let stored = StoredPasskey {
            id: Uuid::now_v7(),
            user_id,
            credential_id: passkey.cred_id().to_vec(),
            credential: serde_json::to_value(&passkey)
                .map_err(|e| AppError::Internal(e.to_string()))?,
            name,
            created_at: now,
            last_used_at: None,
        };
        let tx = self.uow.begin().await?;
        tx.passkeys().add(&stored).await?;
        tx.audit()
            .record(entry(user_id, "auth.passkey_added", stored.id))
            .await?;
        tx.commit().await?;
        Ok(stored)
    }

    pub async fn list(&self, user_id: Uuid) -> AppResult<Vec<StoredPasskey>> {
        Ok(self.uow.passkeys().for_user(user_id).await?)
    }

    /// `NotFound` for an unknown id or someone else's passkey.
    pub async fn remove(&self, user_id: Uuid, id: Uuid) -> AppResult<()> {
        let tx = self.uow.begin().await?;
        if !tx.passkeys().remove(user_id, id).await? {
            return Err(AppError::NotFound);
        }
        tx.audit()
            .record(entry(user_id, "auth.passkey_removed", id))
            .await?;
        tx.commit().await?;
        Ok(())
    }
}

fn entry(user_id: Uuid, action: &str, id: Uuid) -> AuditEntry {
    AuditEntry::member(None, user_id, action, Some(("passkey", id.to_string())))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::Utc;
    use opsagent_core::{passkey::StoredPasskey, repo::SystemClock, user::Email};
    use uuid::Uuid;
    use webauthn_rs_proto::ResidentKeyRequirement;

    use super::*;
    use crate::{actions::uow::Repos, adapters::memory::MemStore, error::AppError};

    fn passkeys(store: &MemStore) -> Passkeys {
        let webauthn = Arc::new(crate::webauthn::build("https://web.test").unwrap());
        Passkeys::new(Arc::new(store.clone()), webauthn, Arc::new(SystemClock))
    }

    async fn user(store: &MemStore, email: &str) -> Uuid {
        let e = Email::parse(email).unwrap();
        store.users().find_or_create_by_email(&e).await.unwrap().id
    }

    async fn stored(store: &MemStore, user_id: Uuid, cred: &[u8]) -> StoredPasskey {
        let p = StoredPasskey {
            id: Uuid::new_v4(),
            user_id,
            credential_id: cred.to_vec(),
            credential: serde_json::json!({}),
            name: "Laptop".into(),
            created_at: Utc::now(),
            last_used_at: None,
        };
        store.passkeys().add(&p).await.unwrap();
        p
    }

    #[tokio::test]
    async fn start_register_requires_resident_key() {
        let store = MemStore::default();
        let ada = user(&store, "ada@example.com").await;
        stored(&store, ada, &[1, 2, 3]).await;
        let (ccr, _state) = passkeys(&store).start_register(ada).await.unwrap();
        let sel = ccr.public_key.authenticator_selection.unwrap();
        assert_eq!(sel.resident_key, Some(ResidentKeyRequirement::Required));
        assert!(sel.require_resident_key);
        let excluded: Vec<Vec<u8>> = ccr
            .public_key
            .exclude_credentials
            .unwrap()
            .iter()
            .map(|c| c.id.to_vec())
            .collect();
        assert_eq!(excluded, vec![vec![1, 2, 3]]);
        assert_eq!(ccr.public_key.user.name, "ada@example.com");
        assert_eq!(ccr.public_key.user.id.to_vec(), ada.as_bytes().to_vec());
    }

    #[tokio::test]
    async fn remove_is_owner_only() {
        let store = MemStore::default();
        let ada = user(&store, "ada@example.com").await;
        let eve = user(&store, "eve@example.com").await;
        let p = stored(&store, ada, &[9]).await;
        let actions = passkeys(&store);
        let err = actions.remove(eve, p.id).await.unwrap_err();
        assert!(matches!(err, AppError::NotFound), "{err:?}");
        let err = actions.remove(ada, Uuid::new_v4()).await.unwrap_err();
        assert!(matches!(err, AppError::NotFound), "{err:?}");
        assert_eq!(actions.list(ada).await.unwrap(), vec![p.clone()]);
        assert!(store.audit_entries().is_empty());

        actions.remove(ada, p.id).await.unwrap();
        assert!(actions.list(ada).await.unwrap().is_empty());
        let entries = store.audit_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, "auth.passkey_removed");
        assert_eq!(entries[0].target, Some(("passkey", p.id.to_string())));
    }
}
