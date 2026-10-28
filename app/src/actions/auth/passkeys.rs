//! Adding, listing and removing a user's passkeys, and signing in with one. Ceremony state stays
//! with the caller.
use std::sync::Arc;

use axum::http::StatusCode;
use opsagent_core::{audit::AuditEntry, passkey::StoredPasskey, repo::Clock};
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, DiscoverableAuthentication, DiscoverableKey, Passkey,
    PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Webauthn,
};
use webauthn_rs_proto::ResidentKeyRequirement;

use super::redeem_magic_link::sign_in_entry;
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

    /// Request options with an empty allow list (the authenticator offers its discoverable
    /// credentials), and the state `finish_login` needs.
    pub fn start_login(&self) -> AppResult<(RequestChallengeResponse, DiscoverableAuthentication)> {
        let (mut rcr, state) = self
            .webauthn
            .start_discoverable_authentication()
            .map_err(|e| AppError::Internal(format!("passkey login: {e}")))?;
        // The library forces conditional (autofill) mediation; the web runs it from a button.
        rcr.mediation = None;
        Ok((rcr, state))
    }

    /// The signed-in user for a verified assertion. An unknown, removed, someone else's or
    /// unverifiable credential is `passkey_invalid` (401); a stored credential that no longer
    /// deserialises is `Internal` (500).
    pub async fn finish_login(
        &self,
        credential: &PublicKeyCredential,
        state: DiscoverableAuthentication,
    ) -> AppResult<Uuid> {
        let (user_id, cred_id) = self
            .webauthn
            .identify_discoverable_authentication(credential)
            .map_err(|_| passkey_invalid())?;
        let stored = self
            .uow
            .passkeys()
            .by_credential_id(cred_id)
            .await?
            .filter(|p| p.user_id == user_id)
            .ok_or_else(passkey_invalid)?;
        let mut passkey: Passkey = serde_json::from_value(stored.credential).map_err(|_| {
            // A row we wrote ourselves that no longer parses is corruption, not a bad assertion.
            tracing::error!(passkey_id = %stored.id, "stored passkey does not deserialise");
            AppError::Internal(format!("stored passkey {} does not deserialise", stored.id))
        })?;
        let result = self
            .webauthn
            .finish_discoverable_authentication(
                credential,
                state,
                &[DiscoverableKey::from(&passkey)],
            )
            .map_err(|e| {
                tracing::info!(error = %e, "passkey assertion rejected");
                passkey_invalid()
            })?;
        passkey.update_credential(&result);
        let credential =
            serde_json::to_value(&passkey).map_err(|e| AppError::Internal(e.to_string()))?;
        let tx = self.uow.begin().await?;
        tx.passkeys()
            .update_after_use(stored.id, &credential, self.clock.now())
            .await?;
        tx.audit().record(sign_in_entry(user_id)).await?;
        tx.commit().await?;
        Ok(user_id)
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

pub(crate) fn passkey_invalid() -> AppError {
    AppError::Refused {
        status: StatusCode::UNAUTHORIZED,
        code: "passkey_invalid",
        detail: "The passkey could not be verified.".into(),
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

    /// A syntactically valid assertion for credential `cred` claiming user handle `user`.
    fn assertion(cred: &[u8], user: Uuid) -> PublicKeyCredential {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
        serde_json::from_value(serde_json::json!({
            "id": B64.encode(cred),
            "rawId": B64.encode(cred),
            "response": {
                "authenticatorData": "",
                "clientDataJSON": "",
                "signature": "",
                "userHandle": B64.encode(user.as_bytes()),
            },
            "type": "public-key",
            "extensions": {},
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn finish_login_with_unknown_or_foreign_credential_is_passkey_invalid() {
        let store = MemStore::default();
        let ada = user(&store, "ada@example.com").await;
        let eve = user(&store, "eve@example.com").await;
        stored(&store, ada, &[4, 5]).await;
        let actions = passkeys(&store);
        // An unknown credential id, and Ada's credential claimed by Eve's user handle.
        for (cred, claimed) in [(&[9u8][..], ada), (&[4, 5][..], eve)] {
            let (rcr, state) = actions.start_login().unwrap();
            assert!(rcr.public_key.allow_credentials.is_empty());
            let err = actions
                .finish_login(&assertion(cred, claimed), state)
                .await
                .unwrap_err();
            assert!(
                matches!(
                    err,
                    AppError::Refused {
                        code: "passkey_invalid",
                        ..
                    }
                ),
                "{err:?}"
            );
        }
        assert!(store.audit_entries().is_empty());
    }

    #[tokio::test]
    async fn finish_login_with_corrupt_stored_credential_is_internal() {
        let store = MemStore::default();
        let ada = user(&store, "ada@example.com").await;
        // `stored` writes `{}`, which is not a serialised `Passkey`.
        stored(&store, ada, &[4, 5]).await;
        let actions = passkeys(&store);
        let (_, state) = actions.start_login().unwrap();
        let err = actions
            .finish_login(&assertion(&[4, 5], ada), state)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Internal(_)), "{err:?}");
        assert!(store.audit_entries().is_empty());
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
