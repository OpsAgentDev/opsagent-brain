use std::sync::Arc;

use axum::http::StatusCode;
use opsagent_core::{repo::RepoError, user::Email};
use uuid::Uuid;

use super::redeem_magic_link::sign_in_entry;
use crate::{
    actions::uow::UnitOfWork,
    error::{AppError, AppResult},
};

/// The Google identity, already exchanged and verified by the controller.
pub struct GoogleProfile {
    /// The OpenID `sub`.
    pub google_id: String,
    /// A verified address (`email_verified` was true).
    pub email: Email,
    pub name: Option<String>,
    /// The `hd` claim: the Workspace domain that manages the account, if any.
    pub hosted_domain: Option<String>,
}

/// Google vouches for the address itself: a Gmail address, or one in the account's own
/// Workspace domain. Only then may an existing user be linked by email, or a new one created
/// (otherwise anyone could pre-register a Google account under someone else's address).
fn google_is_authoritative(email: &Email, hosted_domain: Option<&str>) -> bool {
    let domain = email.as_str().rsplit_once('@').map_or("", |(_, d)| d);
    matches!(domain, "gmail.com" | "googlemail.com")
        || hosted_domain.is_some_and(|hd| hd.trim().eq_ignore_ascii_case(domain))
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
        let authoritative =
            google_is_authoritative(&profile.email, profile.hosted_domain.as_deref());
        let user = tx
            .users()
            .find_or_create_google(
                &profile.google_id,
                &profile.email,
                profile.name,
                authoritative,
            )
            .await
            .map_err(|e| match e {
                RepoError::Conflict("account_exists") => AppError::Refused {
                    status: StatusCode::CONFLICT,
                    code: "account_exists",
                    detail: "An account with this email exists; sign in the way you did before."
                        .into(),
                },
                RepoError::Conflict("google_email_unmanaged") => AppError::Refused {
                    status: StatusCode::CONFLICT,
                    code: "google_email_unmanaged",
                    detail: "Google does not manage this address; sign in with email instead."
                        .into(),
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
    async fn google_sign_in_matches_sub_then_links_email() {
        let store = MemStore::default();
        let email = Email::parse("dev@gmail.com").unwrap();
        let existing = store.users().find_or_create_by_email(&email).await.unwrap();
        let action = SignInGoogle::new(Arc::new(store.clone()));
        let profile = |email: &Email| GoogleProfile {
            google_id: "sub-1".into(),
            email: email.clone(),
            name: Some("Dev".into()),
            hosted_domain: None,
        };
        // First run links the existing user by email.
        assert_eq!(action.run(profile(&email)).await.unwrap(), existing.id);
        assert_one_sign_in(&store, existing.id);
        let user = store.users().get(existing.id).await.unwrap().unwrap();
        assert_eq!(user.google_id.as_deref(), Some("sub-1"));
        // The second run matches on the sub even though the email differs.
        let other = Email::parse("changed@gmail.com").unwrap();
        assert_eq!(action.run(profile(&other)).await.unwrap(), existing.id);
        let n = store
            .audit_entries()
            .iter()
            .filter(|e| e.action == "auth.sign_in")
            .count();
        assert_eq!(n, 2);
    }

    fn profile(sub: &str, email: &str, hd: Option<&str>) -> GoogleProfile {
        GoogleProfile {
            google_id: sub.into(),
            email: Email::parse(email).unwrap(),
            name: None,
            hosted_domain: hd.map(Into::into),
        }
    }

    #[test]
    fn authoritative_only_for_gmail_or_matching_hosted_domain() {
        let e = |s| Email::parse(s).unwrap();
        assert!(google_is_authoritative(&e("a@gmail.com"), None));
        assert!(google_is_authoritative(&e("a@googlemail.com"), None));
        assert!(google_is_authoritative(&e("a@corp.com"), Some("Corp.com")));
        assert!(!google_is_authoritative(&e("a@corp.com"), None));
        assert!(!google_is_authoritative(
            &e("a@corp.com"),
            Some("other.com")
        ));
        assert!(!google_is_authoritative(&e("a@evilgmail.com"), None));
    }

    #[tokio::test]
    async fn custom_domain_links_only_with_matching_hd() {
        let store = MemStore::default();
        let email = Email::parse("a@corp.com").unwrap();
        let existing = store.users().find_or_create_by_email(&email).await.unwrap();
        let action = SignInGoogle::new(Arc::new(store.clone()));
        let refused = action.run(profile("s1", "a@corp.com", None)).await;
        assert!(matches!(
            refused,
            Err(AppError::Refused {
                code: "account_exists",
                ..
            })
        ));
        let id = action
            .run(profile("s1", "a@corp.com", Some("corp.com")))
            .await
            .unwrap();
        assert_eq!(id, existing.id);
    }

    #[tokio::test]
    async fn refuses_to_create_a_user_for_an_unmanaged_address() {
        let store = MemStore::default();
        let action = SignInGoogle::new(Arc::new(store.clone()));
        for hd in [None, Some("other.com")] {
            let res = action.run(profile("s1", "victim@corp.com", hd)).await;
            assert!(matches!(
                res,
                Err(AppError::Refused {
                    code: "google_email_unmanaged",
                    ..
                })
            ));
        }
        let e = Email::parse("victim@corp.com").unwrap();
        assert!(store.users().find_by_email(&e).await.unwrap().is_none());
        assert!(store.audit_entries().is_empty());
        // The managed case still creates the user, and later sign-ins match on the sub.
        let id = action
            .run(profile("s1", "victim@corp.com", Some("corp.com")))
            .await
            .unwrap();
        assert_eq!(
            action
                .run(profile("s1", "victim@corp.com", None))
                .await
                .unwrap(),
            id
        );
    }

    #[tokio::test]
    async fn never_overwrites_a_different_google_id() {
        let store = MemStore::default();
        let action = SignInGoogle::new(Arc::new(store.clone()));
        action
            .run(profile("s1", "a@gmail.com", None))
            .await
            .unwrap();
        let res = action.run(profile("s2", "a@gmail.com", None)).await;
        assert!(matches!(
            res,
            Err(AppError::Refused {
                code: "account_exists",
                ..
            })
        ));
    }
}
