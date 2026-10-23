use std::sync::Arc;

use opsagent_core::audit::AuditEntry;
use uuid::Uuid;

use crate::{
    actions::uow::UnitOfWork,
    error::{AppError, AppResult},
};

/// Removes recipient `id` for owner `actor`.
pub struct DeleteRecipient {
    uow: Arc<dyn UnitOfWork>,
}

impl DeleteRecipient {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(&self, organisation_id: Uuid, actor: Uuid, id: Uuid) -> AppResult<()> {
        let tx = self.uow.begin().await?;
        if !tx.recipients().delete(organisation_id, id).await? {
            return Err(AppError::NotFound);
        }
        let target = Some(("recipient", id.to_string()));
        let entry = AuditEntry::member(Some(organisation_id), actor, "recipient.delete", target);
        tx.audit().record(entry).await?;
        tx.commit().await?;
        Ok(())
    }
}
