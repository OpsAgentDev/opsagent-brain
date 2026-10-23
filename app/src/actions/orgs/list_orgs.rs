use std::sync::Arc;

use opsagent_core::org::{Organisation, Role};
use uuid::Uuid;

use crate::{actions::uow::UnitOfWork, error::AppResult};

/// The live organisations a user belongs to, with the role held.
pub struct ListOrgs {
    uow: Arc<dyn UnitOfWork>,
}

impl ListOrgs {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(&self, user_id: Uuid) -> AppResult<Vec<(Organisation, Role)>> {
        Ok(self.uow.orgs().list_for_user(user_id).await?)
    }
}
