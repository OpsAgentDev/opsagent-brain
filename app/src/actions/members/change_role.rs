use std::sync::Arc;

use axum::http::StatusCode;
use opsagent_core::{
    audit::AuditEntry,
    org::{Member, Role},
};
use uuid::Uuid;

use crate::{
    actions::{orgs::OrgScope, uow::UnitOfWork},
    error::{AppError, AppResult},
};

/// Sets a member's role. The same role is a no-op; demoting the last owner is 409 `last_owner`
/// (checked under the organisation lock, in the transaction that updates). Owners only.
pub struct ChangeRole {
    uow: Arc<dyn UnitOfWork>,
}

impl ChangeRole {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(
        &self,
        scope: &OrgScope,
        actor: Uuid,
        member_id: Uuid,
        role: &str,
    ) -> AppResult<Member> {
        scope.require_owner()?;
        let role = Role::parse(role)
            .ok_or_else(|| AppError::Invalid("role must be owner or member".into()))?;
        let organisation_id = scope.organisation.id;
        let tx = self.uow.begin().await?;
        // Serialise owner changes per org so two concurrent demotions cannot orphan it.
        tx.orgs().lock(organisation_id).await?;
        let target = tx
            .orgs()
            .members(organisation_id)
            .await?
            .into_iter()
            .find(|m| m.id == member_id)
            .ok_or(AppError::NotFound)?;
        if target.role == role {
            return Ok(target);
        }
        if target.role == Role::Owner && tx.orgs().owner_count(organisation_id).await? <= 1 {
            return Err(AppError::Refused {
                status: StatusCode::CONFLICT,
                code: "last_owner",
                detail: "An organisation must keep at least one owner.".into(),
            });
        }
        let updated = tx
            .orgs()
            .set_member_role(organisation_id, member_id, role)
            .await?
            .ok_or(AppError::NotFound)?;
        let target = Some(("member", member_id.to_string()));
        let entry = AuditEntry::member(Some(organisation_id), actor, "member.role", target);
        tx.audit().record(entry).await?;
        tx.commit().await?;
        Ok(updated)
    }
}

#[cfg(test)]
mod tests {
    use opsagent_core::org::OrganisationsRepo;

    use super::*;
    use crate::{actions::orgs::test_support::*, adapters::memory::MemStore};

    #[tokio::test]
    async fn promote_demote_guard_noop_scope_and_owner_only() {
        let store = MemStore::default();
        let (owner, org) = owned_org(&store, "o@example.com", "Acme").await;
        let (_, other) = owned_org(&store, "o2@example.com", "Other").await;
        let mate = user(&store, "m@example.com").await;
        let m = store
            .add_member(org.id, mate.id, Role::Member)
            .await
            .unwrap();
        let foreign = store.members(other.id).await.unwrap()[0].id;
        let change = ChangeRole::new(Arc::new(store.clone()));
        let sc = scope(&store, &org, &owner).await;
        let me = sc.member.id;

        // Last owner cannot be demoted.
        let err = change.run(&sc, owner.id, me, "member").await.unwrap_err();
        let AppError::Refused { status, code, .. } = err else {
            panic!("{err:?}")
        };
        assert_eq!((status, code), (StatusCode::CONFLICT, "last_owner"));
        // Same role: no-op.
        let same = change.run(&sc, owner.id, m.id, "member").await.unwrap();
        assert_eq!(same.role, Role::Member);
        // Promote, then the first owner may step down.
        let up = change.run(&sc, owner.id, m.id, "owner").await.unwrap();
        assert_eq!(up.role, Role::Owner);
        let down = change.run(&sc, owner.id, me, "member").await.unwrap();
        assert_eq!(down.role, Role::Member);
        assert_eq!(store.owner_count(org.id).await.unwrap(), 1);
        // Bad role, other organisation's member.
        let sc = scope(&store, &org, &mate).await;
        let bad = change.run(&sc, mate.id, m.id, "root").await;
        assert!(matches!(bad, Err(AppError::Invalid(_))));
        let r = change.run(&sc, mate.id, foreign, "member").await;
        assert!(matches!(r, Err(AppError::NotFound)), "{r:?}");
        // A plain member is refused (me is a member now).
        let sc = scope(&store, &org, &owner).await;
        let r = change.run(&sc, owner.id, m.id, "member").await;
        assert!(matches!(r, Err(AppError::Forbidden)));
    }
}
