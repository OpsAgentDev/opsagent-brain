use std::sync::Arc;

use opsagent_core::run::Run;
use uuid::Uuid;

use crate::{
    actions::uow::UnitOfWork,
    error::{AppError, AppResult},
};

/// One run of the organisation; `NotFound` for another organisation's.
pub struct GetRun {
    uow: Arc<dyn UnitOfWork>,
}

impl GetRun {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(&self, organisation_id: Uuid, id: Uuid) -> AppResult<Run> {
        let r = self.uow.runs().get(organisation_id, id).await?;
        r.ok_or(AppError::NotFound)
    }
}
