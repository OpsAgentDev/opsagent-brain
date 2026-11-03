use std::sync::Arc;

use axum::http::StatusCode;
use opsagent_core::{
    repo::RepoError,
    user::{Email, SignupAllowlist},
};
use uuid::Uuid;

use super::redeem_magic_link::sign_in_entry;
use crate::{
    actions::uow::UnitOfWork,
    error::{AppError, AppResult},
};

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
    signup: SignupAllowlist,
}

impl SignInGithub {
    pub fn new(uow: Arc<dyn UnitOfWork>, signup: SignupAllowlist) -> Self {
        Self { uow, signup }
    }

    pub async fn run(&self, profile: GithubProfile) -> AppResult<Uuid> {
        let tx = self.uow.begin().await?;
        let user = tx
            .users()
            .find_or_create_github(
                profile.github_id,
                &profile.email,
                profile.name,
                self.signup.allows(&profile.email),
            )
            .await
            .map_err(|e| match e {
                RepoError::Conflict("signup_closed") => AppError::Refused {
                    status: StatusCode::FORBIDDEN,
                    code: "signup_closed",
                    detail: "OpsAgent is in private alpha and sign-ups are closed.".into(),
                },
                e => e.into(),
            })?;
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
        let action = SignInGithub::new(Arc::new(store.clone()), Default::default());
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

    #[tokio::test]
    async fn closed_signup_refuses_new_github_user_but_not_existing() {
        let store = MemStore::default();
        let action = SignInGithub::new(
            Arc::new(store.clone()),
            SignupAllowlist::parse("opsagent.dev"),
        );
        let profile = |id, email: &str| GithubProfile {
            github_id: id,
            email: Email::parse(email).unwrap(),
            name: None,
        };
        let err = action.run(profile(1, "new@gmail.com")).await.unwrap_err();
        assert!(
            matches!(
                err,
                AppError::Refused {
                    status: StatusCode::FORBIDDEN,
                    code: "signup_closed",
                    ..
                }
            ),
            "{err:?}"
        );
        let email = Email::parse("old@gmail.com").unwrap();
        let old = store.users().find_or_create_by_email(&email).await.unwrap();
        assert_eq!(
            action.run(profile(2, "old@gmail.com")).await.unwrap(),
            old.id
        );
        assert_eq!(action.run(profile(2, "x@gmail.com")).await.unwrap(), old.id);
        assert!(action.run(profile(3, "me@opsagent.dev")).await.is_ok());
    }
}
