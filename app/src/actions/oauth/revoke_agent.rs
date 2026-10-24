use std::sync::Arc;

use chrono::{DateTime, Utc};
use opsagent_core::audit::AuditEntry;
use uuid::Uuid;

use crate::{
    actions::{orgs::OrgScope, uow::UnitOfWork},
    error::{AppError, AppResult},
};

/// Revokes one grant: an owner any, a member their own; anything else is a 404.
pub struct RevokeAgent {
    uow: Arc<dyn UnitOfWork>,
}

impl RevokeAgent {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(&self, scope: &OrgScope, grant_id: Uuid, now: DateTime<Utc>) -> AppResult<()> {
        let org = scope.organisation.id;
        let owner = scope.require_owner().is_ok();
        let tx = self.uow.begin().await?;
        let grant = tx
            .oauth()
            .grant(org, grant_id)
            .await?
            .filter(|g| g.revoked_at.is_none() && (owner || g.member_id == scope.member.id))
            .ok_or(AppError::NotFound)?;
        tx.oauth().revoke_grant(org, grant.id, now).await?;
        let target = Some(("oauth_grant", grant.id.to_string()));
        let entry = AuditEntry::member(
            Some(org),
            scope.member.user_id,
            "oauth.grant.revoked",
            target,
        );
        tx.audit().record(entry).await?;
        tx.commit().await?;
        Ok(())
    }
}
