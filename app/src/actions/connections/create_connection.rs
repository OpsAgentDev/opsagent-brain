use std::sync::Arc;

use axum::http::StatusCode;
use opsagent_connectors::{
    registry::{self, ProviderSpec},
    Registry,
};
use opsagent_core::{audit::AuditEntry, connection::NewConnection, org::valid_name};
use opsagent_secrets::Kek;
use uuid::Uuid;

use super::{QuickCreate, TEMPLATE_VERSION};
use crate::{
    actions::{billing::BillingGate, orgs::OrgScope, uow::UnitOfWork},
    creds::{Creds, Dek},
    error::{AppError, AppResult},
};

/// A connection just created, with what the caller needs to show the next step.
pub struct Created {
    pub id: Uuid,
    pub creds: Creds,
    pub spec: ProviderSpec,
}

/// Creates a `pending` connection and its sealed credentials. Owners only; 402 `trial_limit`
/// when a trialing organisation already has its billable connection.
#[derive(Clone)]
pub struct CreateConnection {
    uow: Arc<dyn UnitOfWork>,
    kek: Arc<dyn Kek>,
    registry: Registry,
    gate: BillingGate,
    links: QuickCreate,
}

impl CreateConnection {
    pub fn new(
        uow: Arc<dyn UnitOfWork>,
        kek: Arc<dyn Kek>,
        registry: Registry,
        gate: BillingGate,
        links: QuickCreate,
    ) -> Self {
        Self {
            uow,
            kek,
            registry,
            gate,
            links,
        }
    }

    pub async fn run(
        &self,
        scope: &OrgScope,
        provider: &str,
        display_name: &str,
    ) -> AppResult<Created> {
        scope.require_owner()?;
        let display_name = valid_name(display_name).map_err(|e| AppError::Invalid(e.into()))?;
        // Before any row is written: AWS needs the outbound role to build the onboarding link.
        if provider == "aws" && self.links.principal.is_none() {
            return Err(AppError::Refused {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "connector_unavailable",
                detail: "AWS connections are not available yet.".into(),
            });
        }
        let (organisation_id, actor) = (scope.organisation.id, scope.member.user_id);
        let spec = self
            .registry
            .spec(provider)
            .map_err(|_| AppError::Invalid("provider must be aws".into()))?;
        self.gate
            .require_connection_room(&*self.uow, organisation_id)
            .await?;
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
