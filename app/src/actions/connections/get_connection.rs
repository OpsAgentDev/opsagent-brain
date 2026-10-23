use std::sync::Arc;

use opsagent_core::connection::{Connection, Verification};
use uuid::Uuid;

use crate::{
    actions::uow::UnitOfWork,
    error::{AppError, AppResult},
};

/// One connection with its latest verification; `NotFound` for another organisation's.
pub struct GetConnection {
    uow: Arc<dyn UnitOfWork>,
}

impl GetConnection {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(
        &self,
        organisation_id: Uuid,
        id: Uuid,
    ) -> AppResult<(Connection, Option<Verification>)> {
        let repo = self.uow.connections();
        let c = repo.get(organisation_id, id).await?;
        let c = c.ok_or(AppError::NotFound)?;
        let last = repo.last_verification(organisation_id, id).await?;
        Ok((c, last))
    }
}
