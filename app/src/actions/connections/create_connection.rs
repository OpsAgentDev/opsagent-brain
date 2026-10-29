use std::sync::Arc;

use opsagent_connectors::{
    registry::{self, ProviderSpec},
    Registry,
};
use opsagent_core::{audit::AuditEntry, connection::NewConnection};
use opsagent_secrets::Kek;
use uuid::Uuid;

use super::TEMPLATE_VERSION;
use crate::{
    actions::{billing::BillingGate, uow::UnitOfWork},
    creds::{Creds, Dek},
    error::{AppError, AppResult},
};

/// A connection just created, with what the caller needs to show the next step.
pub struct Created {
    pub id: Uuid,
    pub creds: Creds,
    pub spec: ProviderSpec,
}

/// Creates a `pending` connection and its sealed credentials, for owner `actor`; 402
/// `trial_limit` when a trialing organisation already has its billable connection.
pub struct CreateConnection {
    uow: Arc<dyn UnitOfWork>,
    kek: Arc<dyn Kek>,
    registry: Registry,
    gate: BillingGate,
}

impl CreateConnection {
    pub fn new(
        uow: Arc<dyn UnitOfWork>,
        kek: Arc<dyn Kek>,
        registry: Registry,
        gate: BillingGate,
    ) -> Self {
        Self {
            uow,
            kek,
            registry,
            gate,
        }
    }

    pub async fn run(
        &self,
        organisation_id: Uuid,
        actor: Uuid,
        provider: &str,
        display_name: String,
    ) -> AppResult<Created> {
        let spec = self
            .registry
            .spec(provider)
            .map_err(|_| AppError::Invalid("provider must be aws".into()))?;
        self.gate.require_connection_room(organisation_id).await?;
        let creds = registry::new_creds(provider, Uuid::new_v4().to_string(), &display_name);
        let tx = self.uow.begin().await?;
        let sealed = Dek::of(tx.orgs(), self.kek.as_ref(), organisation_id)
            .await?
            .seal(organisation_id, &creds)?;
        let new = NewConnection {
            organisation_id,
            provider: provider.to_owned(),
            display_name,
            template_version: spec.uses_template.then(|| TEMPLATE_VERSION.to_owned()),
            credential_kind: spec.credential_kind.to_owned(),
        };
        let id = tx.connections().insert(new, sealed).await?.id;
        let target = Some(("connection", id.to_string()));
        let entry = AuditEntry::member(Some(organisation_id), actor, "connection.create", target);
        tx.audit().record(entry).await?;
        tx.commit().await?;
        Ok(Created { id, creds, spec })
    }
}
