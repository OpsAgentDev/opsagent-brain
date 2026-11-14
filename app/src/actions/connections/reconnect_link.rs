use std::sync::Arc;

use axum::http::StatusCode;
use opsagent_connectors::Registry;
use opsagent_core::{audit::AuditEntry, connection::ConnectionStatus as S};
use opsagent_secrets::Kek;
use uuid::Uuid;

use super::Created;
use crate::{
    actions::uow::UnitOfWork,
    creds,
    error::{AppError, AppResult},
};

/// The stored credentials of a `revoked` connection, for owner `actor`, so the caller can show
/// the launch link again and access is repaired without a new connection. Audited; 409
/// `connection_not_revoked` in any other state.
pub struct ReconnectLink {
    uow: Arc<dyn UnitOfWork>,
    kek: Arc<dyn Kek>,
    registry: Registry,
}

impl ReconnectLink {
    pub fn new(uow: Arc<dyn UnitOfWork>, kek: Arc<dyn Kek>, registry: Registry) -> Self {
        Self { uow, kek, registry }
    }

    pub async fn run(&self, organisation_id: Uuid, actor: Uuid, id: Uuid) -> AppResult<Created> {
        let c = self.uow.connections().get(organisation_id, id).await?;
        let c = c.ok_or(AppError::NotFound)?;
        if c.status != S::Revoked {
            return Err(AppError::Refused {
                status: StatusCode::CONFLICT,
                code: "connection_not_revoked",
                detail: "Only a connection that lost access can be reconnected.".into(),
            });
        }
        let spec = self
            .registry
            .spec(&c.provider)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let creds = creds::load(&*self.uow, self.kek.as_ref(), organisation_id, id).await?;
        let target = Some(("connection", id.to_string()));
        let entry = AuditEntry::member(
            Some(organisation_id),
            actor,
            "connection.reconnect_link",
            target,
        );
        self.uow.audit().record(entry).await?;
        Ok(Created { id, creds, spec })
    }
}
