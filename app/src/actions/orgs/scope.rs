use std::sync::Arc;

use opsagent_core::org::{Member, Organisation, Role};
use uuid::Uuid;

use crate::{
    actions::uow::UnitOfWork,
    error::{AppError, AppResult},
};

/// `{org}` (slug) resolved against the session user: a live organisation and the user's
/// membership of it.
#[derive(Debug, Clone)]
pub struct OrgScope {
    pub organisation: Organisation,
    pub member: Member,
}

impl OrgScope {
    pub fn new(organisation: Organisation, member: Member) -> Self {
        Self {
            organisation,
            member,
        }
    }

    pub fn require_owner(&self) -> AppResult<()> {
        if self.member.role == Role::Owner {
            Ok(())
        } else {
            Err(AppError::Forbidden)
        }
    }
}

/// Resolves an `OrgScope`. Anyone who is not a member of a live org gets the same 404 as for
/// an org that does not exist.
pub struct ResolveOrgScope {
    uow: Arc<dyn UnitOfWork>,
}

impl ResolveOrgScope {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(&self, user_id: Uuid, slug: &str) -> AppResult<OrgScope> {
        let (organisation, member) = self
            .uow
            .orgs()
            .membership(slug, user_id)
            .await?
            .ok_or(AppError::NotFound)?;
        Ok(OrgScope::new(organisation, member))
    }
}

#[cfg(test)]
mod tests {
    use crate::{actions::orgs::test_support::*, adapters::memory::MemStore};

    #[tokio::test]
    async fn debug_output_leaves_out_the_wrapped_dek() {
        let store = MemStore::default();
        let (owner, org) = owned_org(&store, "d@example.com", "Keys").await;
        let scope = scope(&store, &org, &owner).await;
        let dek = scope.organisation.wrapped_dek.clone().unwrap();
        let shown = format!("{scope:?}");
        assert!(shown.contains(&org.slug), "{shown}");
        assert!(!shown.contains("wrapped_dek"), "{shown}");
        assert!(!shown.contains(&format!("{dek:?}")), "{shown}");
    }
}
