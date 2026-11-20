use std::sync::Arc;

use opsagent_core::{
    audit::AuditEntry,
    user::{PersonName, User},
};
use uuid::Uuid;

use crate::{
    actions::uow::UnitOfWork,
    error::{AppError, AppResult},
};

/// Renames the signed-in user under the rules a sign-up name follows (`PersonName`), with a
/// `user.update_name` audit row in the same transaction. Nothing else about the account
/// changes here.
pub struct UpdateName {
    uow: Arc<dyn UnitOfWork>,
}

impl UpdateName {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    /// The user as renamed. `Invalid` for a name sign-up would not keep.
    pub async fn run(&self, user_id: Uuid, name: &str) -> AppResult<User> {
        let name = PersonName::parse(name).ok_or_else(|| {
            AppError::Invalid("name must be 1 to 80 characters, with no control characters".into())
        })?;
        let tx = self.uow.begin().await?;
        let user = tx.users().get(user_id).await?;
        let user = user.ok_or(AppError::Unauthenticated)?;
        tx.users().set_name(user_id, &name).await?;
        let target = Some(("user", user_id.to_string()));
        let entry = AuditEntry::member(None, user_id, "user.update_name", target);
        tx.audit().record(entry).await?;
        tx.commit().await?;
        Ok(User {
            name: Some(name.as_str().to_owned()),
            ..user
        })
    }
}

#[cfg(test)]
mod tests {
    use opsagent_core::{audit::Actor, user::UsersRepo};

    use super::*;
    use crate::{actions::orgs::test_support::user, adapters::memory::MemStore};

    #[tokio::test]
    async fn renames_trimmed_and_audits_once() {
        let store = MemStore::default();
        let u = user(&store, "pat@example.com").await;
        let rename = UpdateName::new(Arc::new(store.clone()));
        let got = rename.run(u.id, "  Pat Smith ").await.unwrap();
        assert_eq!(got.name.as_deref(), Some("Pat Smith"));
        assert_eq!((got.id, &got.email), (u.id, &u.email));
        // A named user is renamed too.
        rename.run(u.id, "Patricia").await.unwrap();
        let stored = UsersRepo::get(&store, u.id).await.unwrap().unwrap();
        assert_eq!(stored.name.as_deref(), Some("Patricia"));
        let audit: Vec<_> = store
            .audit_entries()
            .into_iter()
            .filter(|e| e.action == "user.update_name")
            .collect();
        assert_eq!(audit.len(), 2, "{audit:?}");
        assert_eq!(audit[0].actor, Actor::Member(u.id));
        assert_eq!(audit[0].target, Some(("user", u.id.to_string())));
        assert_eq!(audit[0].organisation_id, None);
    }

    #[tokio::test]
    async fn an_unusable_name_changes_and_audits_nothing() {
        let store = MemStore::default();
        let u = user(&store, "pat@example.com").await;
        let rename = UpdateName::new(Arc::new(store.clone()));
        rename.run(u.id, "Pat").await.unwrap();
        for bad in ["", "   ", "a\u{7}b", &"x".repeat(81)] {
            let err = rename.run(u.id, bad).await.unwrap_err();
            assert!(matches!(err, AppError::Invalid(_)), "{bad:?}: {err:?}");
        }
        let stored = UsersRepo::get(&store, u.id).await.unwrap().unwrap();
        assert_eq!(stored.name.as_deref(), Some("Pat"));
        assert_eq!(store.audit_entries().len(), 1);
    }

    #[tokio::test]
    async fn an_unknown_user_is_unauthenticated() {
        let rename = UpdateName::new(Arc::new(MemStore::default()));
        let err = rename.run(Uuid::new_v4(), "Pat").await.unwrap_err();
        assert!(matches!(err, AppError::Unauthenticated), "{err:?}");
    }
}
