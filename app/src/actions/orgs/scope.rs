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
    // shortcut: copies of `member.user_id` and `organisation.id` for the controllers Tasks 7-12
    // have not moved yet; drop them when the last `scope.organisation_id` caller is gone.
    pub user_id: Uuid,
    pub organisation_id: Uuid,
}

impl OrgScope {
    pub fn new(organisation: Organisation, member: Member) -> Self {
        Self {
            user_id: member.user_id,
            organisation_id: organisation.id,
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
