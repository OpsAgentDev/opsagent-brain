//! OAuth use cases (nothing here names MCP; the resource URL comes from config).
mod decide_consent;
mod exchange_code;
mod get_consent;
mod list_agents;
mod refresh_grant;
mod register_client;
mod resolve_client;
mod revoke_agent;
mod revoke_token;
mod start_authorization;

use chrono::{DateTime, Duration, Utc};
use opsagent_core::{
    audit::AuditEntry,
    oauth::{AccessToken, Grant, RefreshToken, SCOPE},
    org::Member,
    repo::RepoResult,
};
use serde::Serialize;
use uuid::Uuid;

use crate::{
    actions::uow::Repos,
    controllers::oauth::OAuthError,
    tokens::{hash_token, new_token},
};

pub use decide_consent::{DecideConsent, Decision};
pub use get_consent::{ConsentView, GetConsent};
pub use list_agents::{Agent, ListAgents};
pub use register_client::{RegisterClient, RegistrationRequest};
pub use resolve_client::ResolveClient;
pub use revoke_agent::RevokeAgent;
pub use start_authorization::{AuthorizeError, AuthorizeParams, StartAuthorization};

pub use exchange_code::{CodeExchange, ExchangeCode};
pub use refresh_grant::RefreshGrant;
pub use revoke_token::RevokeToken;

pub const CONSENT_TTL_SECS: i64 = 600;
pub const CODE_TTL_SECS: i64 = 60;
pub const ACCESS_TTL_SECS: i64 = 3600;
pub const REFRESH_TTL_DAYS: i64 = 30;
pub const REFRESH_GRACE_SECS: i64 = 30;

pub struct OAuth {
    pub register_client: RegisterClient,
    pub resolve_client: ResolveClient,
    pub start_authorization: StartAuthorization,
    pub get_consent: GetConsent,
    pub decide_consent: DecideConsent,
    pub exchange_code: ExchangeCode,
    pub refresh_grant: RefreshGrant,
    pub revoke_token: RevokeToken,
    pub list_agents: ListAgents,
    pub revoke_agent: RevokeAgent,
}

/// The RFC 6749 section 5.1 success body.
#[derive(Debug, Clone, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    pub refresh_token: String,
    pub scope: &'static str,
}

fn internal(e: impl std::fmt::Display) -> OAuthError {
    tracing::error!(error = %e, "oauth token store failed");
    OAuthError::server_error()
}

/// A fresh access token and a refresh token with id `refresh_id` for `grant`.
async fn mint(
    repos: &dyn Repos,
    grant: &Grant,
    refresh_id: Uuid,
    now: DateTime<Utc>,
) -> RepoResult<TokenResponse> {
    let (access, refresh) = (new_token(), new_token());
    repos
        .oauth()
        .insert_refresh(&RefreshToken {
            id: refresh_id,
            grant_id: grant.id,
            organisation_id: grant.organisation_id,
            token_hash: hash_token(&refresh),
            expires_at: now + Duration::days(REFRESH_TTL_DAYS),
            spent_at: None,
            successor_id: None,
            grace_reissued_at: None,
        })
        .await?;
    repos
        .oauth()
        .insert_access(&AccessToken {
            id: Uuid::new_v4(),
            grant_id: grant.id,
            organisation_id: grant.organisation_id,
            token_hash: hash_token(&access),
            expires_at: now + Duration::seconds(ACCESS_TTL_SECS),
        })
        .await?;
    Ok(TokenResponse {
        access_token: access,
        token_type: "Bearer",
        expires_in: ACCESS_TTL_SECS,
        refresh_token: refresh,
        scope: SCOPE,
    })
}

/// The member a grant names, while they still belong to its live organisation.
async fn live_member(
    repos: &dyn Repos,
    organisation_id: Uuid,
    member_id: Uuid,
) -> RepoResult<Option<Member>> {
    if repos.orgs().is_deleted(organisation_id).await? {
        return Ok(None);
    }
    let members = repos.orgs().members(organisation_id).await?;
    Ok(members.into_iter().find(|m| m.id == member_id))
}

/// Revokes a grant and records `oauth.grant.revoked` with `outcome` (why), in `repos`. The
/// actor is the grant's user while they are a member; otherwise the system.
async fn revoke_audited(
    repos: &dyn Repos,
    organisation_id: Uuid,
    grant_id: Uuid,
    member_id: Uuid,
    outcome: &str,
    now: DateTime<Utc>,
) -> RepoResult<()> {
    tracing::warn!(grant_id = %grant_id, outcome, "oauth grant revoked");
    repos
        .oauth()
        .revoke_grant(organisation_id, grant_id, now)
        .await?;
    let target = ("oauth_grant", grant_id.to_string());
    let action = "oauth.grant.revoked";
    let entry = match live_member(repos, organisation_id, member_id).await? {
        Some(m) => AuditEntry {
            outcome: outcome.into(),
            ..AuditEntry::member(Some(organisation_id), m.user_id, action, Some(target))
        },
        None => AuditEntry::system(organisation_id, action, target, outcome),
    };
    repos.audit().record(entry).await
}

/// `redirect_uri` with the present `pairs` and `iss` (RFC 9207) appended to its query.
pub fn redirect_with(redirect_uri: &str, pairs: &[(&str, Option<&str>)], iss: &str) -> String {
    let Ok(mut url) = reqwest::Url::parse(redirect_uri) else {
        // Registered URIs are validated, so this is unreachable in practice.
        return redirect_uri.to_owned();
    };
    {
        let mut q = url.query_pairs_mut();
        for (k, v) in pairs {
            if let Some(v) = v {
                q.append_pair(k, v);
            }
        }
        q.append_pair("iss", iss);
    }
    url.into()
}

#[cfg(test)]
mod tests {
    use super::redirect_with;

    #[test]
    fn redirect_keeps_existing_query_and_encodes() {
        let u = redirect_with(
            "https://a.example/cb?x=1",
            &[("state", Some("a b&c")), ("code", None)],
            "https://brain.example",
        );
        assert_eq!(
            u,
            "https://a.example/cb?x=1&state=a+b%26c&iss=https%3A%2F%2Fbrain.example"
        );
    }
}
