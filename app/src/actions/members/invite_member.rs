use std::sync::Arc;

use chrono::Duration;
use opsagent_core::{
    audit::AuditEntry,
    org::{Invite, Role},
    repo::Clock,
    user::Email,
};
use uuid::Uuid;

use crate::{
    actions::{billing::BillingGate, orgs::OrgScope, uow::UnitOfWork},
    error::{AppError, AppResult},
    mailers::{magic_link as mail, Mailer},
    tokens::{hash_token, new_token},
};

/// Creates a 7-day invite and mails its link (`{web_base_url}/invites/{token}`). Owners only;
/// 402 `plan_limit` at the tier's member limit.
pub struct InviteMember {
    uow: Arc<dyn UnitOfWork>,
    mailer: Arc<dyn Mailer>,
    web_base_url: String,
    clock: Arc<dyn Clock>,
    gate: BillingGate,
}

impl InviteMember {
    pub fn new(
        uow: Arc<dyn UnitOfWork>,
        mailer: Arc<dyn Mailer>,
        web_base_url: String,
        clock: Arc<dyn Clock>,
        gate: BillingGate,
    ) -> Self {
        Self {
            uow,
            mailer,
            web_base_url,
            clock,
            gate,
        }
    }

    pub async fn run(
        &self,
        scope: &OrgScope,
        actor: Uuid,
        email: &str,
        role: &str,
    ) -> AppResult<Invite> {
        scope.require_owner()?;
        let email = Email::parse(email).ok_or_else(|| AppError::Invalid("invalid email".into()))?;
        let role = Role::parse(role)
            .ok_or_else(|| AppError::Invalid("role must be owner or member".into()))?;
        let org = &scope.organisation;
        self.gate.require_plan_room(org.id, true).await?;
        let token = new_token();
        let expires = self.clock.now() + Duration::days(7);
        let tx = self.uow.begin().await?;
        let row = tx
            .orgs()
            .insert_invite(org.id, &email, role, &hash_token(&token), expires)
            .await?;
        let target = Some(("invite", row.id.to_string()));
        let entry = AuditEntry::member(Some(org.id), actor, "invite.create", target);
        tx.audit().record(entry).await?;
        tx.commit().await?;
        let link = format!("{}/invites/{token}", self.web_base_url);
        let sent = self
            .mailer
            .send(mail::invite(email.as_str(), &org.name, &link));
        if let Err(e) = sent.await {
            tracing::error!(error = %e, "invite mail failed");
        }
        Ok(row)
    }
}
