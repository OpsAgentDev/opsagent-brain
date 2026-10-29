use std::sync::Arc;

use opsagent_core::{audit::AuditEntry, repo::Clock};
use uuid::Uuid;

use crate::{
    actions::{billing::enqueue_sync, uow::UnitOfWork},
    error::AppResult,
};

use super::end_connection;

/// Disconnects for owner `actor`; already disconnected is a no-op (idempotent DELETE). The
/// billable count is resynced (it stays billable to the period's end).
pub struct DisconnectConnection {
    uow: Arc<dyn UnitOfWork>,
    clock: Arc<dyn Clock>,
}

impl DisconnectConnection {
    pub fn new(uow: Arc<dyn UnitOfWork>, clock: Arc<dyn Clock>) -> Self {
        Self { uow, clock }
    }

    pub async fn run(&self, organisation_id: Uuid, actor: Uuid, id: Uuid) -> AppResult<()> {
        let tx = self.uow.begin().await?;
        if !end_connection(&*tx, organisation_id, id, "customer_disconnected").await? {
            return Ok(());
        }
        let target = Some(("connection", id.to_string()));
        let entry = AuditEntry::member(
            Some(organisation_id),
            actor,
            "connection.disconnect",
            target,
        );
        tx.audit().record(entry).await?;
        enqueue_sync(&*tx, organisation_id, self.clock.now()).await?;
        tx.commit().await?;
        Ok(())
    }
}
