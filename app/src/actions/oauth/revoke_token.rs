use std::sync::Arc;

use chrono::{DateTime, Utc};

use super::internal;
use crate::{actions::uow::UnitOfWork, controllers::oauth::OAuthError, tokens::hash_token};

/// RFC 7009: an access or refresh token revokes its whole grant; an unknown token is not an
/// error.
pub struct RevokeToken {
    uow: Arc<dyn UnitOfWork>,
}

impl RevokeToken {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(&self, token: &str, now: DateTime<Utc>) -> Result<(), OAuthError> {
        let repo = self.uow.oauth();
        let hash = hash_token(token);
        let found = match repo.access_by_hash(&hash).await.map_err(internal)? {
            Some((t, _)) => Some((t.organisation_id, t.grant_id)),
            None => repo
                .refresh_by_hash(&hash)
                .await
                .map_err(internal)?
                .map(|t| (t.organisation_id, t.grant_id)),
        };
        if let Some((org, grant)) = found {
            repo.revoke_grant(org, grant, now).await.map_err(internal)?;
        }
        Ok(())
    }
}
