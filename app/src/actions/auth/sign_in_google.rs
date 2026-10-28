use std::sync::Arc;

use opsagent_core::user::Email;
use uuid::Uuid;

use super::redeem_magic_link::sign_in_entry;
use crate::{actions::uow::UnitOfWork, error::AppResult};

/// The Google identity, already exchanged and verified by the controller.
pub struct GoogleProfile {
    /// The OpenID `sub`.
    pub google_id: String,
    /// A verified address (`email_verified` was true).
    pub email: Email,
    pub name: Option<String>,
}

/// Finds or links the user for a Google identity and records the sign-in.
pub struct SignInGoogle {
    uow: Arc<dyn UnitOfWork>,
}

impl SignInGoogle {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(&self, profile: GoogleProfile) -> AppResult<Uuid> {
        let tx = self.uow.begin().await?;
        let user = tx
            .users()
            .find_or_create_google(&profile.google_id, &profile.email, profile.name)
            .await?;
        tx.audit().record(sign_in_entry(user.id)).await?;
        tx.commit().await?;
        Ok(user.id)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use opsagent_core::user::Email;

    use super::*;
    use crate::{
        actions::{auth::test_support::assert_one_sign_in, uow::Repos},
        adapters::memory::MemStore,
    };

    #[tokio::test]
    async fn google_sign_in_matches_sub_then_links_email() {
        let store = MemStore::default();
        let email = Email::parse("dev@example.com").unwrap();
        let existing = store.users().find_or_create_by_email(&email).await.unwrap();
        let action = SignInGoogle::new(Arc::new(store.clone()));
        let profile = |email: &Email| GoogleProfile {
            google_id: "sub-1".into(),
            email: email.clone(),
            name: Some("Dev".into()),
        };
        // First run links the existing user by email.
        assert_eq!(action.run(profile(&email)).await.unwrap(), existing.id);
        assert_one_sign_in(&store, existing.id);
        let user = store.users().get(existing.id).await.unwrap().unwrap();
        assert_eq!(user.google_id.as_deref(), Some("sub-1"));
        // The second run matches on the sub even though the email differs.
        let other = Email::parse("changed@example.com").unwrap();
        assert_eq!(action.run(profile(&other)).await.unwrap(), existing.id);
        let n = store
            .audit_entries()
            .iter()
            .filter(|e| e.action == "auth.sign_in")
            .count();
        assert_eq!(n, 2);
    }
}
