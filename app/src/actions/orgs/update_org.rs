use std::sync::Arc;

use opsagent_core::{
    org::{Organisation, OrganisationPatch},
    repo::Clock,
};

use super::{valid_name, valid_timezone, OrgScope};
use crate::{actions::uow::UnitOfWork, error::AppResult};

/// Renames the organisation or moves its zone; owners only.
pub struct UpdateOrg {
    uow: Arc<dyn UnitOfWork>,
    clock: Arc<dyn Clock>,
}

impl UpdateOrg {
    pub fn new(uow: Arc<dyn UnitOfWork>, clock: Arc<dyn Clock>) -> Self {
        Self { uow, clock }
    }

    /// `patch` holds the raw request values; they are validated here.
    pub async fn run(&self, scope: &OrgScope, patch: OrganisationPatch) -> AppResult<Organisation> {
        scope.require_owner()?;
        let patch = OrganisationPatch {
            name: patch.name.as_deref().map(valid_name).transpose()?,
            timezone: patch.timezone.as_deref().map(valid_timezone).transpose()?,
        };
        // A new zone moves every schedule with it, in the same transaction.
        let tx = self.uow.begin().await?;
        let tz = patch.timezone.clone();
        let org = tx.orgs().update(scope.organisation.id, patch).await?;
        if let Some(tz) = tz.filter(|t| *t != scope.organisation.timezone) {
            tx.schedules()
                .set_timezone(org.id, &tz, self.clock.now())
                .await?;
        }
        tx.commit().await?;
        Ok(org)
    }
}
