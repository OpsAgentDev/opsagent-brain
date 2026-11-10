use std::sync::Arc;

use opsagent_core::{org::Invite, repo::Clock};

use crate::{actions::orgs::OrgScope, actions::uow::UnitOfWork, error::AppResult};

/// The organisation's pending, unexpired invites, newest first. Owners only.
pub struct ListInvites {
    uow: Arc<dyn UnitOfWork>,
    clock: Arc<dyn Clock>,
}

impl ListInvites {
    pub fn new(uow: Arc<dyn UnitOfWork>, clock: Arc<dyn Clock>) -> Self {
        Self { uow, clock }
    }

    pub async fn run(&self, scope: &OrgScope) -> AppResult<Vec<Invite>> {
        scope.require_owner()?;
        let id = scope.organisation.id;
        Ok(self.uow.orgs().list_invites(id, self.clock.now()).await?)
    }
}

#[cfg(test)]
mod tests {
    use opsagent_core::{
        org::{OrganisationsRepo, Role},
        user::Email,
    };

    use super::*;
    use crate::{actions::orgs::test_support::*, adapters::memory::MemStore, error::AppError};

    #[tokio::test]
    async fn lists_pending_newest_first_to_owners_only_and_per_org() {
        let store = MemStore::default();
        let (owner, org) = owned_org(&store, "o@example.com", "Acme").await;
        let (owner2, org2) = owned_org(&store, "o2@example.com", "Other").await;
        let soon = chrono::Utc::now() + chrono::Duration::days(1);
        let past = chrono::Utc::now() - chrono::Duration::days(1);
        let orgs = |s: &MemStore| -> Arc<dyn UnitOfWork> { Arc::new(s.clone()) };
        let uow = orgs(&store);
        for (o, mail, at) in [
            (&org, "a@example.com", soon),
            (&org, "b@example.com", soon),
            (&org, "old@example.com", past),
            (&org2, "x@example.com", soon),
        ] {
            let e = Email::parse(mail).unwrap();
            let r = uow
                .orgs()
                .insert_invite(o.id, &e, Role::Member, mail, at)
                .await;
            r.unwrap();
        }
        let list = ListInvites::new(uow, Arc::new(opsagent_core::repo::SystemClock));
        let sc = scope(&store, &org, &owner).await;
        let got = list.run(&sc).await.unwrap();
        let emails: Vec<_> = got.iter().map(|i| i.email.as_str()).collect();
        assert_eq!(emails, ["b@example.com", "a@example.com"]);

        let sc2 = scope(&store, &org2, &owner2).await;
        assert_eq!(list.run(&sc2).await.unwrap().len(), 1);

        let mate = user(&store, "m@example.com").await;
        store
            .add_member(org.id, mate.id, Role::Member)
            .await
            .unwrap();
        let sc3 = scope(&store, &org, &mate).await;
        assert!(matches!(list.run(&sc3).await, Err(AppError::Forbidden)));
    }
}
