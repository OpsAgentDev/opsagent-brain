use std::sync::Arc;

use opsagent_core::{
    audit::AuditEntry,
    connection::{transition, Connection, ConnectionEvent as E},
};
use uuid::Uuid;

use crate::{
    actions::uow::{Repos, UnitOfWork},
    error::{AppError, AppResult},
};

/// Disconnects for owner `actor`; already disconnected is a no-op (idempotent DELETE).
pub struct DisconnectConnection {
    uow: Arc<dyn UnitOfWork>,
}

impl DisconnectConnection {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(&self, organisation_id: Uuid, actor: Uuid, id: Uuid) -> AppResult<()> {
        let tx = self.uow.begin().await?;
        let c = tx.connections().get(organisation_id, id).await?;
        let c = c.ok_or(AppError::NotFound)?;
        if !end(&*tx, c, "customer_disconnected").await? {
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
        tx.commit().await?;
        Ok(())
    }
}

/// Moves `c` to `disconnected` with `reason` through `repos` (the caller's transaction);
/// `false` if it already was. A status changed since `c` was read is re-read and retried.
pub async fn end(repos: &dyn Repos, mut c: Connection, reason: &str) -> AppResult<bool> {
    let (org, id) = (c.organisation_id, c.id);
    loop {
        let Ok(to) = transition(c.status, E::Disconnect) else {
            return Ok(false);
        };
        let cas = repos
            .connections()
            .cas_status(org, id, c.status, to, Some(reason));
        if cas.await? {
            return Ok(true);
        }
        c = repos
            .connections()
            .get(org, id)
            .await?
            .ok_or(AppError::NotFound)?;
    }
}
