use std::sync::Arc;

use opsagent_deliver::repo::Integration;
use uuid::Uuid;

use crate::{actions::uow::UnitOfWork, error::AppResult};

pub struct ListIntegrations {
    uow: Arc<dyn UnitOfWork>,
}

impl ListIntegrations {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(&self, organisation_id: Uuid) -> AppResult<Vec<Integration>> {
        Ok(self.uow.integrations().list(organisation_id).await?)
    }
}
