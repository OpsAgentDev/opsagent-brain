use std::sync::Arc;

use axum::http::StatusCode;
use chrono::{DurationRound, TimeDelta};
use opsagent_connectors::{registry, ConnectorError};
use opsagent_core::{
    audit::AuditEntry,
    connection::{transition, Connection, ConnectionEvent as E, ConnectionStatus as S},
    repo::Clock,
    run::RunKey,
};
use opsagent_ledger::JobKind;
use opsagent_secrets::Kek;
use uuid::Uuid;

use super::disconnected;
use crate::{
    actions::{runs::RunDispatcher, uow::UnitOfWork},
    creds::{self, Creds},
    error::{AppError, AppResult},
};

fn refused(code: &'static str, detail: &str) -> AppError {
    AppError::Refused {
        status: StatusCode::CONFLICT,
        code,
        detail: detail.into(),
    }
}

fn role_error(e: ConnectorError, service: &str) -> AppError {
    match e {
        ConnectorError::InvalidCredentials(m) => AppError::Invalid(m),
        e => {
            // The code only: provider text can name the customer's role and account.
            tracing::error!(error_code = %e.code(), service, "reported role check failed");
            AppError::Internal("reported role check failed".into())
        }
    }
}

/// Stores the reported role and queues a `verify` run; returns the run id.
pub struct RequestVerify {
    uow: Arc<dyn UnitOfWork>,
    kek: Arc<dyn Kek>,
    dispatcher: Arc<RunDispatcher>,
    clock: Arc<dyn Clock>,
}

impl RequestVerify {
    pub fn new(
        uow: Arc<dyn UnitOfWork>,
        kek: Arc<dyn Kek>,
        dispatcher: Arc<RunDispatcher>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            uow,
            kek,
            dispatcher,
            clock,
        }
    }

    pub async fn run(
        &self,
        organisation_id: Uuid,
        actor: Uuid,
        id: Uuid,
        role_arn: &str,
    ) -> AppResult<Uuid> {
        let c = self.uow.connections().get(organisation_id, id).await?;
        let c = c.ok_or(AppError::NotFound)?;
        let from = c.status;
        if from == S::Disconnected {
            return Err(disconnected());
        }
        let creds = self.with_reported_role(&c, role_arn).await?;
        let to = match from {
            S::Pending => transition(from, E::StackReported),
            S::Revoked => transition(from, E::RoleReturned),
            s => Ok(s),
        }
        .map_err(|e| AppError::Internal(e.to_string()))?;
        let tx = self.uow.begin().await?;
        creds::save(&*tx, self.kek.as_ref(), organisation_id, id, &creds).await?;
        // Guarded on the status read above, so a concurrent Disconnect or worker outcome is not lost.
        let cas = tx
            .connections()
            .cas_status(organisation_id, id, from, to, None);
        if !cas.await? {
            return Err(refused(
                "connection_state_changed",
                "The connection changed while this request ran. Reload and try again.",
            ));
        }
        let target = Some(("connection", id.to_string()));
        let entry = AuditEntry::member(
            Some(organisation_id),
            actor,
            "connection.verify_requested",
            target,
        );
        tx.audit().record(entry).await?;
        tx.commit().await?;
        // A duplicate request in the same minute is the same run.
        let now = self.clock.now();
        let key = RunKey {
            organisation_id: Some(organisation_id),
            connection_id: Some(id),
            job_type: JobKind::Verify.as_str().into(),
            scheduled_at: now
                .duration_trunc(TimeDelta::minutes(1))
                .map_err(|e| AppError::Internal(e.to_string()))?,
        };
        Ok(self.dispatcher.enqueue(key, now).await?.run.id)
    }

    /// The stored credentials with the reported role. A live connection only re-verifies the
    /// role it was verified with: scans must never run under a role that has not passed
    /// verification.
    async fn with_reported_role(&self, c: &Connection, raw: &str) -> AppResult<Creds> {
        let role =
            registry::reported_role(&c.provider, raw).map_err(|e| role_error(e, &c.provider))?;
        let kek = self.kek.as_ref();
        let mut creds = creds::load(&*self.uow, kek, c.organisation_id, c.id).await?;
        let live = matches!(c.status, S::Connected | S::Degraded);
        if role.is_some() && role != creds.role_arn && live {
            return Err(refused(
                "role_change_requires_reconnect",
                "This connection is verified with a different role. Disconnect it and connect again to use a new role.",
            ));
        }
        if role.is_some() {
            creds.role_arn = role;
        }
        Ok(creds)
    }
}
