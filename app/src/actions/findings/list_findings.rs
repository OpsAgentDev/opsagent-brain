use std::sync::Arc;

use opsagent_core::{
    finding::{Finding, FindingFilter},
    repo::{FindingCursor, PageOf, PageRequest},
};
use uuid::Uuid;

use crate::{actions::uow::UnitOfWork, error::AppResult};

/// The organisation's findings, most severe first, then oldest.
#[derive(Clone)]
pub struct ListFindings {
    uow: Arc<dyn UnitOfWork>,
}

impl ListFindings {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(
        &self,
        organisation_id: Uuid,
        filter: FindingFilter,
        page: PageRequest<FindingCursor>,
    ) -> AppResult<PageOf<Finding, FindingCursor>> {
        Ok(self
            .uow
            .findings()
            .list(organisation_id, filter, page)
            .await?)
    }
}
