use std::sync::Arc;

use chrono::{DateTime, Utc};
use opsagent_core::audit::AuditEntry;

use super::internal;
use crate::{actions::uow::UnitOfWork, controllers::oauth::OAuthError, tokens::hash_token};

/// RFC 7009: an access or refresh token revokes its whole grant; an unknown token is not an
/// error. A live grant's revocation is audited as the client's own act.
pub struct RevokeToken {
    uow: Arc<dyn UnitOfWork>,
}

impl RevokeToken {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(&self, token: &str, now: DateTime<Utc>) -> Result<(), OAuthError> {
        let tx = self.uow.begin().await.map_err(internal)?;
        let repo = tx.oauth();
        let hash = hash_token(token);
        let found = match repo.access_by_hash(&hash).await.map_err(internal)? {
            Some((t, _)) => Some((t.organisation_id, t.grant_id)),
            None => repo
                .refresh_by_hash(&hash)
                .await
                .map_err(internal)?
                .map(|t| (t.organisation_id, t.grant_id)),
        };
        let Some((org, grant)) = found else {
            return Ok(());
        };
        let live = repo
            .grant(org, grant)
            .await
            .map_err(internal)?
            .is_some_and(|g| g.revoked_at.is_none());
        if !live {
            return Ok(());
        }
        repo.revoke_grant(org, grant, now).await.map_err(internal)?;
        let entry = AuditEntry {
            target: Some(("oauth_grant", grant.to_string())),
            ..AuditEntry::mcp_client(org, grant, "oauth.grant.revoked", "client_revoked")
        };
        tx.audit().record(entry).await.map_err(internal)?;
        tx.commit().await.map_err(internal)
    }
}
