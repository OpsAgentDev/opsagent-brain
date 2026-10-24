use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use opsagent_core::repo::RepoError;
use uuid::Uuid;

use super::{internal, live_member, mint, revoke_audited, TokenResponse, REFRESH_GRACE_SECS};
use crate::{
    actions::uow::{Tx, UnitOfWork},
    controllers::oauth::OAuthError,
    tokens::hash_token,
};

/// `refresh_token`: rotates the refresh token. Inside the grace window a spent token gets one
/// more successor (two racing refreshes); any other reuse revokes the grant.
pub struct RefreshGrant {
    uow: Arc<dyn UnitOfWork>,
}

fn bad() -> OAuthError {
    OAuthError::invalid_grant("The refresh token is invalid.")
}

/// `Ok(false)` when the row was already marked (`NotFound`).
fn marked(r: Result<(), RepoError>) -> Result<bool, OAuthError> {
    match r {
        Ok(()) => Ok(true),
        Err(RepoError::NotFound) => Ok(false),
        Err(e) => Err(internal(e)),
    }
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
        let (org, member) = (grant.organisation_id, grant.member_id);
        let tx = self.uow.begin().await.map_err(internal)?;
        if live_member(tx.as_ref(), org, member)
            .await
            .map_err(internal)?
            .is_none()
        {
            return refuse(tx, org, grant.id, member, "member_gone", now).await;
        }
        let successor = Uuid::new_v4();
        let in_grace = |at: DateTime<Utc>| now - at < Duration::seconds(REFRESH_GRACE_SECS);
        let o = tx.oauth();
        let allowed = match rt.spent_at {
            None => {
                // A racing refresh that spent it first leaves this one the grace reissue.
                marked(o.spend_refresh(org, rt.id, successor, now).await)?
                    || marked(o.mark_grace_reissued(org, rt.id, now).await)?
            }
            Some(at) if in_grace(at) => marked(o.mark_grace_reissued(org, rt.id, now).await)?,
            Some(_) => false,
        };
        if !allowed {
            return refuse(tx, org, grant.id, member, "refresh_reuse", now).await;
        }
        let tokens = mint(tx.as_ref(), &grant, successor, now)
            .await
            .map_err(internal)?;
        o.touch_grant(org, grant.id, now).await.map_err(internal)?;
        tx.commit().await.map_err(internal)?;
        Ok(tokens)
    }
}

/// Revokes the grant (audited with `outcome`), commits, and answers `invalid_grant`.
async fn refuse(
    tx: Box<dyn Tx>,
    org: Uuid,
    grant_id: Uuid,
    member_id: Uuid,
    outcome: &str,
    now: DateTime<Utc>,
) -> Result<TokenResponse, OAuthError> {
    revoke_audited(tx.as_ref(), org, grant_id, member_id, outcome, now)
        .await
        .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    Err(bad())
}
