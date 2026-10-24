use std::sync::Arc;

use axum::http::StatusCode;
use opsagent_core::{audit::AuditEntry, org::Role};
use uuid::Uuid;

use crate::{
    actions::{orgs::OrgScope, uow::UnitOfWork},
    error::{AppError, AppResult},
};

/// Removes a member; refused with `last_owner` if it would leave no owner. Owners only.
pub struct RemoveMember {
    uow: Arc<dyn UnitOfWork>,
}

impl RemoveMember {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(&self, scope: &OrgScope, actor: Uuid, member_id: Uuid) -> AppResult<()> {
        scope.require_owner()?;
        let organisation_id = scope.organisation.id;
        let tx = self.uow.begin().await?;
        // Serialise owner removals per org so two concurrent requests cannot orphan it.
        tx.orgs().lock(organisation_id).await?;
        let target = tx
            .orgs()
            .members(organisation_id)
            .await?
            .into_iter()
            .find(|m| m.id == member_id)
            .ok_or(AppError::NotFound)?;
        if target.role == Role::Owner && tx.orgs().owner_count(organisation_id).await? <= 1 {
            return Err(AppError::Refused {
                status: StatusCode::CONFLICT,
                code: "last_owner",
                detail: "An organisation must keep at least one owner.".into(),
            });
        }
        // Also cancels the user's pending invites, so they cannot rejoin through one.
        tx.orgs().remove_member(organisation_id, member_id).await?;
        let target = Some(("member", member_id.to_string()));
        let entry = AuditEntry::member(Some(organisation_id), actor, "member.remove", target);
        tx.audit().record(entry).await?;
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use opsagent_core::org::OrganisationsRepo;

    use super::*;
    use crate::{actions::orgs::test_support::*, adapters::memory::MemStore};

    #[tokio::test]
    async fn remove_last_owner_refused() {
        let store = MemStore::default();
        let (owner, org) = owned_org(&store, "only@example.com", "Solo").await;
        let scope = scope(&store, &org, &owner).await;
        let remove = RemoveMember::new(Arc::new(store.clone()));
        let err = remove
            .run(&scope, owner.id, scope.member.id)
            .await
            .unwrap_err();
        let AppError::Refused { status, code, .. } = err else {
            panic!("{err:?}")
        };
        assert_eq!((status, code), (StatusCode::CONFLICT, "last_owner"));
        assert_eq!(store.owner_count(org.id).await.unwrap(), 1);

        // With a second owner, the first may go.
        let other = user(&store, "two@example.com").await;
        store
            .add_member(org.id, other.id, Role::Owner)
            .await
            .unwrap();
        remove.run(&scope, owner.id, scope.member.id).await.unwrap();
        let left = store.members(org.id).await.unwrap();
        assert_eq!(
            left.iter().map(|m| m.user_id).collect::<Vec<_>>(),
            [other.id]
        );
    }
}
