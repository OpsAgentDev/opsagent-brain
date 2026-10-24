use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use opsagent_core::repo::RepoError;

use super::{internal, mint, TokenResponse, REFRESH_GRACE_SECS};
use crate::{actions::uow::UnitOfWork, controllers::oauth::OAuthError, tokens::hash_token};

/// `refresh_token`: rotates the refresh token. A spent token within the grace window gets
/// another successor (two racing refreshes); after it, reuse revokes the grant.
pub struct RefreshGrant {
    uow: Arc<dyn UnitOfWork>,
}

impl RefreshGrant {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(
        &self,
        refresh_token: &str,
        client_id: &str,
        now: DateTime<Utc>,
    ) -> Result<TokenResponse, OAuthError> {
        let bad = || OAuthError::invalid_grant("The refresh token is invalid.");
        let repo = self.uow.oauth();
        let rt = repo
            .refresh_by_hash(&hash_token(refresh_token))
            .await
            .map_err(internal)?
            .filter(|t| t.expires_at > now)
            .ok_or_else(bad)?;
        let grant = repo
            .grant(rt.organisation_id, rt.grant_id)
            .await
            .map_err(internal)?
            .filter(|g| g.revoked_at.is_none() && g.client_id == client_id)
            .ok_or_else(bad)?;
        if rt
            .spent_at
            .is_some_and(|at| now - at >= Duration::seconds(REFRESH_GRACE_SECS))
        {
            tracing::warn!(grant_id = %grant.id, "spent refresh token reused; grant revoked");
            repo.revoke_grant(grant.organisation_id, grant.id, now)
                .await
                .map_err(internal)?;
            return Err(bad());
        }
        let tx = self.uow.begin().await.map_err(internal)?;
        let (tokens, successor) = mint(tx.as_ref(), &grant, now).await.map_err(internal)?;
        if rt.spent_at.is_none() {
            // NotFound: a racing refresh spent it a moment ago, which is inside the grace window.
            match tx
                .oauth()
                .spend_refresh(rt.organisation_id, rt.id, successor, now)
                .await
            {
                Ok(()) | Err(RepoError::NotFound) => {}
                Err(e) => return Err(internal(e)),
            }
        }
        tx.oauth()
            .touch_grant(grant.organisation_id, grant.id, now)
            .await
            .map_err(internal)?;
        tx.commit().await.map_err(internal)?;
        Ok(tokens)
    }
}
