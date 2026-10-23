use std::sync::Arc;

use opsagent_core::user::Email;
use uuid::Uuid;

use super::redeem_magic_link::sign_in_entry;
use crate::{actions::uow::UnitOfWork, error::AppResult};

/// The GitHub identity, already exchanged and verified by the controller.
pub struct GithubProfile {
    pub github_id: i64,
    /// The verified primary address.
    pub email: Email,
    pub name: Option<String>,
}

/// Finds or links the user for a GitHub identity and records the sign-in.
pub struct SignInGithub {
    uow: Arc<dyn UnitOfWork>,
}

impl SignInGithub {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(&self, profile: GithubProfile) -> AppResult<Uuid> {
        let tx = self.uow.begin().await?;
        let user = tx
            .users()
            .find_or_create_github(profile.github_id, &profile.email, profile.name)
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
    async fn github_sign_in_links_existing_email() {
        let store = MemStore::default();
        let email = Email::parse("dev@example.com").unwrap();
        let existing = store.users().find_or_create_by_email(&email).await.unwrap();
        let action = SignInGithub::new(Arc::new(store.clone()));
        let profile = || GithubProfile {
            github_id: 42,
            email: email.clone(),
            name: Some("Dev".into()),
        };
        assert_eq!(action.run(profile()).await.unwrap(), existing.id);
        assert_one_sign_in(&store, existing.id);
        // The second sign-in matches on the GitHub id.
        assert_eq!(action.run(profile()).await.unwrap(), existing.id);
        let user = store.users().get(existing.id).await.unwrap().unwrap();
        assert_eq!(user.github_id, Some(42));
        assert_eq!(user.name.as_deref(), Some("Dev"));
    }
}
