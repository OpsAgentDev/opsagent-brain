use std::sync::Arc;

use opsagent_core::audit::AuditEntry;
use uuid::Uuid;

use crate::{
    actions::{orgs::OrgScope, uow::UnitOfWork},
    error::{AppError, AppResult},
};

/// Revokes a pending invite, so its link answers 410. Idempotent: an invite already revoked,
/// accepted or expired is left as it is. Another organisation's invite is a 404. Owners only.
pub struct RevokeInvite {
    uow: Arc<dyn UnitOfWork>,
}

impl RevokeInvite {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(&self, scope: &OrgScope, actor: Uuid, invite_id: Uuid) -> AppResult<()> {
        scope.require_owner()?;
        let organisation_id = scope.organisation.id;
        let tx = self.uow.begin().await?;
        if !tx.orgs().revoke_invite(organisation_id, invite_id).await? {
            return Err(AppError::NotFound);
        }
        let target = Some(("invite", invite_id.to_string()));
        let entry = AuditEntry::member(Some(organisation_id), actor, "invite.revoke", target);
        tx.audit().record(entry).await?;
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use opsagent_core::{
        org::{OrganisationsRepo, Role},
        user::Email,
    };

    use super::*;
    use crate::{actions::orgs::test_support::*, adapters::memory::MemStore};

    #[tokio::test]
    async fn revoke_is_idempotent_scoped_and_owner_only() {
        let store = MemStore::default();
        let (owner, org) = owned_org(&store, "o@example.com", "Acme").await;
        let (_, other) = owned_org(&store, "o2@example.com", "Other").await;
        let mail = Email::parse("new@example.com").unwrap();
        let exp = Utc::now() + Duration::days(7);
        let mk = |org_id| store.insert_invite(org_id, &mail, Role::Member, "tok", exp);
        let inv = mk(org.id).await.unwrap();
        let foreign = store
            .insert_invite(other.id, &mail, Role::Member, "tok2", exp)
            .await
            .unwrap();
        let revoke = RevokeInvite::new(Arc::new(store.clone()));
        let sc = scope(&store, &org, &owner).await;

        revoke.run(&sc, owner.id, inv.id).await.unwrap();
        revoke.run(&sc, owner.id, inv.id).await.unwrap();
        // The link now answers like an expired one.
        assert!(store
            .take_invite("tok", Utc::now())
            .await
            .unwrap()
            .is_none());
        // Other organisation's invite, and unknown ids: 404, and untouched.
        for id in [foreign.id, Uuid::new_v4()] {
            let r = revoke.run(&sc, owner.id, id).await;
            assert!(matches!(r, Err(AppError::NotFound)), "{r:?}");
        }
        assert!(store
            .take_invite("tok2", Utc::now())
            .await
            .unwrap()
            .is_some());

        let mate = user(&store, "m@example.com").await;
        store
            .add_member(org.id, mate.id, Role::Member)
            .await
            .unwrap();
        let sc = scope(&store, &org, &mate).await;
        let r = revoke.run(&sc, mate.id, inv.id).await;
        assert!(matches!(r, Err(AppError::Forbidden)));
    }
}
