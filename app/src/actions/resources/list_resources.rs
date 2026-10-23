use std::sync::Arc;

use opsagent_core::{
    repo::{PageOf, PageRequest},
    resource::{ResourceFilter, ResourceRow},
};
use uuid::Uuid;

use crate::{actions::uow::UnitOfWork, error::AppResult};

/// The organisation's inventory, newest first.
pub struct ListResources {
    uow: Arc<dyn UnitOfWork>,
}

impl ListResources {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(
        &self,
        organisation_id: Uuid,
        filter: ResourceFilter,
        page: PageRequest,
    ) -> AppResult<PageOf<ResourceRow>> {
        Ok(self
            .uow
            .resources()
            .list(organisation_id, filter, page)
            .await?)
    }
}
