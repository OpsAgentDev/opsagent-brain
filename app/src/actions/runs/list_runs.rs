use std::sync::Arc;

use opsagent_core::{
    repo::{PageOf, PageRequest},
    run::{Run, RunFilter},
};
use uuid::Uuid;

use crate::{actions::uow::UnitOfWork, error::AppResult};

/// The organisation's runs, newest first.
pub struct ListRuns {
    uow: Arc<dyn UnitOfWork>,
}

impl ListRuns {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(
        &self,
        organisation_id: Uuid,
        filter: RunFilter,
        page: PageRequest,
    ) -> AppResult<PageOf<Run>> {
        Ok(self.uow.runs().list(organisation_id, filter, page).await?)
    }
}
