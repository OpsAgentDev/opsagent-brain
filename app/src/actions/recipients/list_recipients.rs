use std::sync::Arc;

use opsagent_core::repo::{PageOf, PageRequest};
use opsagent_deliver::repo::RecipientRow;
use uuid::Uuid;

use crate::{actions::uow::UnitOfWork, error::AppResult};

/// The organisation's recipients, newest first.
pub struct ListRecipients {
    uow: Arc<dyn UnitOfWork>,
}

impl ListRecipients {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(
        &self,
        organisation_id: Uuid,
        page: PageRequest,
    ) -> AppResult<PageOf<RecipientRow>> {
        Ok(self.uow.recipients().list(organisation_id, page).await?)
    }
}
