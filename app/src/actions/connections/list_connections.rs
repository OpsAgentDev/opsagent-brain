use std::sync::Arc;

use opsagent_core::connection::Connection;
use uuid::Uuid;

use crate::{actions::uow::UnitOfWork, error::AppResult};

/// Every connection of the organisation, oldest first (unpaged: the route returns an array).
pub struct ListConnections {
    uow: Arc<dyn UnitOfWork>,
}

impl ListConnections {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(&self, organisation_id: Uuid) -> AppResult<Vec<Connection>> {
        Ok(self.uow.connections().list(organisation_id).await?)
    }
}
