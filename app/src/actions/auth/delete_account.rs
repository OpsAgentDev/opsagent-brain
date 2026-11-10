use std::sync::Arc;

use axum::http::StatusCode;
use opsagent_core::{audit::AuditEntry, org::Role, repo::Clock};
use uuid::Uuid;

use crate::{
    actions::uow::UnitOfWork,
    error::{AppError, AppResult},
};

/// Deletes the signed-in user's account (PRD: refused while they are the only owner of an
/// organisation). Leaves every organisation the way member removal does, then erases the user,
/// in one transaction. The caller flushes the session; other sessions die on their next request
/// because the user no longer resolves.
pub struct DeleteAccount {
    uow: Arc<dyn UnitOfWork>,
    clock: Arc<dyn Clock>,
}

impl DeleteAccount {
    pub fn new(uow: Arc<dyn UnitOfWork>, clock: Arc<dyn Clock>) -> Self {
        Self { uow, clock }
    }

    /// `confirm` must be the account's email (any case).
    pub async fn run(&self, user_id: Uuid, confirm: &str) -> AppResult<()> {
        let user = self
            .uow
            .users()
            .get(user_id)
            .await?
            .ok_or(AppError::Unauthenticated)?;
        if !confirm.trim().eq_ignore_ascii_case(user.email.as_str()) {
            return Err(AppError::Refused {
                status: StatusCode::UNPROCESSABLE_ENTITY,
                code: "confirm_mismatch",
                detail: "Type your email address exactly to confirm.".into(),
            });
        }
        let tx = self.uow.begin().await?;
        let mut orgs = tx.orgs().list_for_user(user_id).await?;
        // A fixed lock order, so two concurrent deletions cannot deadlock.
        orgs.sort_by_key(|(o, _)| o.id);
        for (o, _) in &orgs {
            tx.orgs().lock(o.id).await?;
        }
        let mut sole = Vec::new();
        for (o, role) in &orgs {
            if *role == Role::Owner && tx.orgs().owner_count(o.id).await? <= 1 {
                sole.push(o.name.clone());
            }
        }
        if !sole.is_empty() {
            return Err(AppError::Refused {
                status: StatusCode::CONFLICT,
                code: "last_owner",
                detail: format!(
                    "You are the only owner of {}. Make someone else an owner, or delete the organisation, first.",
                    sole.join(", ")
                ),
            });
        }
        let now = self.clock.now();
        for (o, _) in &orgs {
            let members = tx.orgs().members(o.id).await?;
            let Some(m) = members.into_iter().find(|m| m.user_id == user_id) else {
                continue;
            };
            // Same effects as RemoveMember: membership (and with it chat history) gone,
            // pending invites to them cancelled, their grants revoked.
            tx.orgs().remove_member(o.id, m.id).await?;
            tx.oauth().revoke_member_grants(o.id, m.id, now).await?;
            let target = Some(("member", m.id.to_string()));
            let entry = AuditEntry::member(Some(o.id), user_id, "member.remove", target);
            tx.audit().record(entry).await?;
        }
        tx.users().erase(user_id, now).await?;
        let target = Some(("user", user_id.to_string()));
        tx.audit()
            .record(AuditEntry::member(None, user_id, "user.delete", target))
            .await?;
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use opsagent_core::{org::OrganisationsRepo, repo::SystemClock, user::UsersRepo};

    use super::*;
    use crate::{actions::orgs::test_support::*, adapters::memory::MemStore};

    fn action(store: &MemStore) -> DeleteAccount {
        DeleteAccount::new(Arc::new(store.clone()), Arc::new(SystemClock))
    }

    fn refused(err: AppError) -> (StatusCode, &'static str, String) {
        let AppError::Refused {
            status,
            code,
            detail,
        } = err
        else {
            panic!("{err:?}")
        };
        (status, code, detail)
    }

    #[tokio::test]
    async fn the_email_must_be_typed_to_confirm() {
        let store = MemStore::default();
        let u = user(&store, "pat@example.com").await;
        let (status, code, _) = refused(action(&store).run(u.id, "pat@").await.unwrap_err());
        assert_eq!((status, code), (StatusCode::UNPROCESSABLE_ENTITY, "confirm_mismatch"));
        assert!(UsersRepo::get(&store, u.id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn the_only_owner_is_refused_and_told_which_organisation() {
        let store = MemStore::default();
        let (owner, org) = owned_org(&store, "only@example.com", "Solo").await;
        let (status, code, detail) =
            refused(action(&store).run(owner.id, "ONLY@example.com").await.unwrap_err());
        assert_eq!((status, code), (StatusCode::CONFLICT, "last_owner"));
        assert!(detail.contains("Solo"), "{detail}");
        assert_eq!(store.members(org.id).await.unwrap().len(), 1);
        assert!(UsersRepo::get(&store, owner.id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn a_member_is_removed_everywhere_and_the_account_is_erased() {
        let store = MemStore::default();
        let (owner, org) = owned_org(&store, "boss@example.com", "Acme").await;
        let pat = user(&store, "pat@example.com").await;
        store.add_member(org.id, pat.id, Role::Member).await.unwrap();
        // Pat co-owns a second organisation with someone else, so leaving it is allowed.
        let (other_owner, org2) = owned_org(&store, "sam@example.com", "Beta").await;
        store.add_member(org2.id, pat.id, Role::Owner).await.unwrap();

        action(&store).run(pat.id, " pat@example.com ").await.unwrap();

        assert!(UsersRepo::get(&store, pat.id).await.unwrap().is_none());
        let email = opsagent_core::user::Email::parse("pat@example.com").unwrap();
        assert!(store.find_by_email(&email).await.unwrap().is_none());
        for (o, left) in [(org.id, owner.id), (org2.id, other_owner.id)] {
            let ids: Vec<_> = store.members(o).await.unwrap().into_iter().map(|m| m.user_id).collect();
            assert_eq!(ids, [left]);
        }
        let actions: Vec<_> = store.audit_entries().into_iter().map(|e| e.action).collect();
        assert_eq!(actions.iter().filter(|a| *a == "member.remove").count(), 2);
        assert!(actions.iter().any(|a| a == "user.delete"));
    }
}
