use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    oauth::{
        AccessToken, ClientKind, ConsentRequest, Grant, OAuthClient, OAuthRepo, RefreshToken,
        DYNAMIC_CLIENT_TTL_DAYS,
    },
    repo::{RepoError, RepoResult},
};
use uuid::Uuid;

use super::MemStore;

#[async_trait]
impl OAuthRepo for MemStore {
    async fn upsert_client(&self, c: &OAuthClient) -> RepoResult<()> {
        let mut s = self.state();
        match s
            .oauth_clients
            .iter_mut()
            .find(|x| x.client_id == c.client_id)
        {
            Some(x) => {
                let last_used_at = x.last_used_at;
                *x = OAuthClient {
                    last_used_at,
                    ..c.clone()
                };
            }
            None => s.oauth_clients.push(c.clone()),
        }
        Ok(())
    }

    async fn client(&self, client_id: &str) -> RepoResult<Option<OAuthClient>> {
        let s = self.state();
        Ok(s.oauth_clients
            .iter()
            .find(|c| c.client_id == client_id)
            .cloned())
    }

    async fn touch_client(&self, client_id: &str, now: DateTime<Utc>) -> RepoResult<()> {
        let mut s = self.state();
        if let Some(c) = s
            .oauth_clients
            .iter_mut()
            .find(|c| c.client_id == client_id)
        {
            c.last_used_at = Some(now);
            if c.kind == ClientKind::Dynamic {
                c.expires_at = Some(now + chrono::Duration::days(DYNAMIC_CLIENT_TTL_DAYS));
            }
        }
        Ok(())
    }

    async fn client_has_live_grant(&self, client_id: &str) -> RepoResult<bool> {
        let s = self.state();
        Ok(s.oauth_grants
            .iter()
            .any(|g| g.client_id == client_id && g.revoked_at.is_none()))
    }

    async fn insert_consent(&self, r: &ConsentRequest) -> RepoResult<()> {
        let mut s = self.state();
        s.oauth_consents.push(r.clone());
        Ok(())
    }

    async fn consent(&self, id: Uuid) -> RepoResult<Option<ConsentRequest>> {
        let s = self.state();
        Ok(s.oauth_consents.iter().find(|c| c.id == id).cloned())
    }

    async fn decide_consent(
        &self,
        id: Uuid,
        member_id: Uuid,
        organisation_id: Uuid,
        code_hash: &str,
        code_expires_at: DateTime<Utc>,
    ) -> RepoResult<()> {
        let mut s = self.state();
        let c = s
            .oauth_consents
            .iter_mut()
            .find(|c| c.id == id)
            .ok_or(RepoError::NotFound)?;
        c.member_id = Some(member_id);
        c.organisation_id = Some(organisation_id);
        c.code_hash = Some(code_hash.into());
        c.code_expires_at = Some(code_expires_at);
        Ok(())
    }

    async fn consume_code(
        &self,
        code_hash: &str,
        now: DateTime<Utc>,
    ) -> RepoResult<Option<ConsentRequest>> {
        let mut s = self.state();
        let found = s.oauth_consents.iter_mut().find(|c| {
            c.code_hash.as_deref() == Some(code_hash)
                && c.code_used_at.is_none()
                && c.code_expires_at.is_some_and(|t| t > now)
        });
        Ok(found.map(|c| {
            c.code_used_at = Some(now);
            c.clone()
        }))
    }

    async fn consent_by_code_hash(&self, code_hash: &str) -> RepoResult<Option<ConsentRequest>> {
        let s = self.state();
        Ok(s.oauth_consents
            .iter()
            .find(|c| c.code_hash.as_deref() == Some(code_hash))
            .cloned())
    }

    async fn set_consent_grant(&self, id: Uuid, grant_id: Uuid) -> RepoResult<()> {
        let mut s = self.state();
        let c = s
            .oauth_consents
            .iter_mut()
            .find(|c| c.id == id)
            .ok_or(RepoError::NotFound)?;
        c.grant_id = Some(grant_id);
        Ok(())
    }

    async fn insert_grant(&self, g: &Grant) -> RepoResult<()> {
        self.state().oauth_grants.push(g.clone());
        Ok(())
    }

    async fn grant(&self, organisation_id: Uuid, id: Uuid) -> RepoResult<Option<Grant>> {
        let s = self.state();
        Ok(s.oauth_grants
            .iter()
            .find(|g| (g.organisation_id, g.id) == (organisation_id, id))
            .cloned())
    }

    async fn grants_for_org(&self, organisation_id: Uuid) -> RepoResult<Vec<Grant>> {
        let s = self.state();
        let mut rows: Vec<Grant> = s
            .oauth_grants
            .iter()
            .filter(|g| g.organisation_id == organisation_id && g.revoked_at.is_none())
            .cloned()
            .collect();
        rows.sort_by_key(|g| (g.created_at, g.id));
        Ok(rows)
    }

    async fn insert_refresh(&self, t: &RefreshToken) -> RepoResult<()> {
        let mut s = self.state();
        s.oauth_refresh.push(t.clone());
        Ok(())
    }

    async fn refresh_by_hash(&self, token_hash: &str) -> RepoResult<Option<RefreshToken>> {
        let s = self.state();
        Ok(s.oauth_refresh
            .iter()
            .find(|r| r.token_hash == token_hash)
            .cloned())
    }

    async fn spend_refresh(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        successor_id: Uuid,
        now: DateTime<Utc>,
    ) -> RepoResult<()> {
        let mut s = self.state();
        let t = s
            .oauth_refresh
            .iter_mut()
            .find(|r| (r.organisation_id, r.id) == (organisation_id, id) && r.spent_at.is_none())
            .ok_or(RepoError::NotFound)?;
        t.spent_at = Some(now);
        t.successor_id = Some(successor_id);
        Ok(())
    }

    async fn insert_access(&self, t: &AccessToken) -> RepoResult<()> {
        let mut s = self.state();
        s.oauth_access.push(t.clone());
        Ok(())
    }

    async fn access_by_hash(&self, token_hash: &str) -> RepoResult<Option<(AccessToken, Grant)>> {
        let s = self.state();
        let Some(t) = s.oauth_access.iter().find(|a| a.token_hash == token_hash) else {
            return Ok(None);
        };
        let g = s
            .oauth_grants
            .iter()
            .find(|g| (g.organisation_id, g.id) == (t.organisation_id, t.grant_id))
            .ok_or_else(|| RepoError::Storage("access token without grant".into()))?;
        Ok(Some((t.clone(), g.clone())))
    }

    async fn revoke_grant(
        &self,
        organisation_id: Uuid,
        grant_id: Uuid,
        now: DateTime<Utc>,
    ) -> RepoResult<()> {
        revoke(self, now, |g| {
            (g.organisation_id, g.id) == (organisation_id, grant_id)
        });
        Ok(())
    }

    async fn revoke_member_grants(
        &self,
        organisation_id: Uuid,
        member_id: Uuid,
        now: DateTime<Utc>,
    ) -> RepoResult<()> {
        revoke(self, now, |g| {
            (g.organisation_id, g.member_id) == (organisation_id, member_id)
        });
        Ok(())
    }

    async fn revoke_org_grants(&self, organisation_id: Uuid, now: DateTime<Utc>) -> RepoResult<()> {
        revoke(self, now, |g| g.organisation_id == organisation_id);
        Ok(())
    }

    async fn touch_grant(
        &self,
        organisation_id: Uuid,
        grant_id: Uuid,
        now: DateTime<Utc>,
    ) -> RepoResult<()> {
        let mut s = self.state();
        if let Some(g) = s
            .oauth_grants
            .iter_mut()
            .find(|g| (g.organisation_id, g.id) == (organisation_id, grant_id))
        {
            g.last_used_at = Some(now);
        }
        Ok(())
    }
}

/// Stamps `revoked_at` on the unrevoked grants `matches` selects.
fn revoke(store: &MemStore, now: DateTime<Utc>, matches: impl Fn(&Grant) -> bool) {
    let mut s = store.state();
    for g in s
        .oauth_grants
        .iter_mut()
        .filter(|g| g.revoked_at.is_none() && matches(g))
    {
        g.revoked_at = Some(now);
    }
}
