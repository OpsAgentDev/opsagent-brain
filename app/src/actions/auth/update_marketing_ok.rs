use std::sync::Arc;

use opsagent_core::{audit::AuditEntry, user::User};
use uuid::Uuid;

use crate::{
    actions::uow::UnitOfWork,
    error::{AppError, AppResult},
};

/// Sets the signed-in user's opt-in to hear about other Binary Labs products, with a
/// `user.update_marketing_ok` audit row in the same transaction.
pub struct UpdateMarketingOk {
    uow: Arc<dyn UnitOfWork>,
}

impl UpdateMarketingOk {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    /// The user as updated.
    pub async fn run(&self, user_id: Uuid, marketing_ok: bool) -> AppResult<User> {
        let tx = self.uow.begin().await?;
        let user = tx.users().get(user_id).await?;
        let user = user.ok_or(AppError::Unauthenticated)?;
        tx.users().set_marketing_ok(user_id, marketing_ok).await?;
        let target = Some(("user", user_id.to_string()));
        let entry = AuditEntry::member(None, user_id, "user.update_marketing_ok", target);
        tx.audit().record(entry).await?;
        tx.commit().await?;
        Ok(User {
            marketing_ok,
            ..user
        })
    }
}

#[cfg(test)]
mod tests {
    use opsagent_core::user::UsersRepo;

    use super::*;
    use crate::{actions::orgs::test_support::user, adapters::memory::MemStore};

    #[tokio::test]
    async fn opts_in_and_out_and_audits_each() {
        let store = MemStore::default();
        let pat = user(&store, "pat@example.com").await;
        let act = UpdateMarketingOk::new(Arc::new(store.clone()));
        assert!(act.run(pat.id, true).await.unwrap().marketing_ok);
        assert!(store.get(pat.id).await.unwrap().unwrap().marketing_ok);
        assert!(!act.run(pat.id, false).await.unwrap().marketing_ok);
        let n = store
            .audit_entries()
            .iter()
            .filter(|e| e.action == "user.update_marketing_ok")
            .count();
        assert_eq!(n, 2);
    }
}
