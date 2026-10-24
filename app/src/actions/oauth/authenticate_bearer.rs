use std::sync::Arc;

use chrono::{DateTime, Utc};
use opsagent_core::oauth::{AccessToken, Grant};

use super::live_member;
use crate::{
    actions::{
        orgs::{OrgScope, ResolveOrgScope},
        uow::UnitOfWork,
    },
    error::{AppError, AppResult},
    tokens::hash_token,
};

/// A live access token, its grant, and the grant's member scope as of now.
#[derive(Debug, Clone)]
pub struct Bearer {
    pub token: AccessToken,
    pub grant: Grant,
    pub scope: OrgScope,
}

/// Resolves a presented access token on every call, so expiry, revocation and a member's
/// removal or role change take effect on the next request. `None`: refuse with 401.
pub struct AuthenticateBearer {
    uow: Arc<dyn UnitOfWork>,
    resolve_scope: ResolveOrgScope,
}

impl AuthenticateBearer {
    pub fn new(uow: Arc<dyn UnitOfWork>, resolve_scope: ResolveOrgScope) -> Self {
        Self { uow, resolve_scope }
    }

    pub async fn run(&self, token: &str, now: DateTime<Utc>) -> AppResult<Option<Bearer>> {
        let Some((token, grant)) = self.uow.oauth().access_by_hash(&hash_token(token)).await?
        else {
            return Ok(None);
        };
        if token.expires_at <= now || grant.revoked_at.is_some() {
            return Ok(None);
        }
        // The grant names the membership row; the scope is resolved for its user.
        let org = grant.organisation_id;
        let Some(member) = live_member(self.uow.as_ref(), org, grant.member_id).await? else {
            return Ok(None);
        };
        let scope = match self.resolve_scope.run_by_id(member.user_id, org).await {
            Ok(s) if s.member.id == grant.member_id => s,
            Ok(_) | Err(AppError::NotFound) => return Ok(None),
            Err(e) => return Err(e),
        };
        Ok(Some(Bearer {
            token,
            grant,
            scope,
        }))
    }
}

/// Records a grant's use (`last_used_at`, shown on Connected agents).
pub struct TouchGrant {
    uow: Arc<dyn UnitOfWork>,
}

impl TouchGrant {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(&self, grant: &Grant, now: DateTime<Utc>) -> AppResult<()> {
        let o = self.uow.oauth();
        Ok(o.touch_grant(grant.organisation_id, grant.id, now).await?)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::{Duration, Utc};
    use opsagent_core::oauth::{AccessToken, Grant};
    use uuid::Uuid;

    use super::*;
    use crate::{
        actions::{orgs::test_support::*, uow::Repos},
        adapters::memory::MemStore,
        tokens::hash_token,
    };

    async fn setup(expires_in: Duration) -> (MemStore, AuthenticateBearer, Grant) {
        let store = MemStore::default();
        let (owner, org) = owned_org(&store, "b@example.com", "Bearer").await;
        let member = scope(&store, &org, &owner).await.member;
        let grant = Grant {
            id: Uuid::new_v4(),
            client_id: "c".into(),
            member_id: member.id,
            organisation_id: org.id,
            created_at: Utc::now(),
            last_used_at: None,
            revoked_at: None,
        };
        store.oauth().insert_grant(&grant).await.unwrap();
        let token = AccessToken {
            id: Uuid::new_v4(),
            grant_id: grant.id,
            organisation_id: org.id,
            token_hash: hash_token("tok"),
            expires_at: Utc::now() + expires_in,
        };
        store.oauth().insert_access(&token).await.unwrap();
        let uow = Arc::new(store.clone());
        let auth = AuthenticateBearer::new(uow.clone(), ResolveOrgScope::new(uow));
        (store, auth, grant)
    }

    #[tokio::test]
    async fn live_token_resolves_and_expired_or_revoked_do_not() {
        let (store, auth, grant) = setup(Duration::hours(1)).await;
        let got = auth.run("tok", Utc::now()).await.unwrap().unwrap();
        assert_eq!(got.scope.organisation.id, grant.organisation_id);
        assert!(auth.run("other", Utc::now()).await.unwrap().is_none());
        let later = Utc::now() + Duration::hours(2);
        assert!(auth.run("tok", later).await.unwrap().is_none());
        let o = store.oauth();
        o.revoke_grant(grant.organisation_id, grant.id, Utc::now())
            .await
            .unwrap();
        assert!(auth.run("tok", Utc::now()).await.unwrap().is_none());
    }
}
