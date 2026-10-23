use std::sync::Arc;

use opsagent_core::org::{Organisation, OrganisationPatch};

use super::{valid_name, valid_timezone, OrgScope};
use crate::{actions::uow::UnitOfWork, error::AppResult};

/// Renames the organisation or moves its zone; owners only.
pub struct UpdateOrg {
    uow: Arc<dyn UnitOfWork>,
}

impl UpdateOrg {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    /// `patch` holds the raw request values; they are validated here.
    pub async fn run(&self, scope: &OrgScope, patch: OrganisationPatch) -> AppResult<Organisation> {
        scope.require_owner()?;
        let patch = OrganisationPatch {
            name: patch.name.as_deref().map(valid_name).transpose()?,
            timezone: patch.timezone.as_deref().map(valid_timezone).transpose()?,
        };
        Ok(self.uow.orgs().update(scope.organisation.id, patch).await?)
    }
}
