use std::sync::Arc;

use opsagent_core::org::Role;
use uuid::Uuid;

use crate::{actions::uow::UnitOfWork, error::AppResult};

/// Whether a user owns at least one live organisation.
pub struct IsOwnerAnywhere {
    uow: Arc<dyn UnitOfWork>,
}

impl IsOwnerAnywhere {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(&self, user_id: Uuid) -> AppResult<bool> {
        let orgs = self.uow.orgs().list_for_user(user_id).await?;
        Ok(orgs.iter().any(|(_, role)| *role == Role::Owner))
    }
}
