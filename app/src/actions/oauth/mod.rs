//! OAuth use cases (nothing here names MCP; the resource URL comes from config).
mod decide_consent;
mod exchange_code;
mod get_consent;
mod refresh_grant;
mod register_client;
mod resolve_client;
mod revoke_token;
mod start_authorization;

use chrono::{DateTime, Duration, Utc};
use opsagent_core::{
    oauth::{AccessToken, Grant, RefreshToken, SCOPE},
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
pub use register_client::{RegisterClient, RegistrationRequest};
pub use resolve_client::ResolveClient;
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

/// A fresh access and refresh token for `grant`; also returns the refresh token's id.
async fn mint(
    repos: &dyn Repos,
    grant: &Grant,
    now: DateTime<Utc>,
) -> RepoResult<(TokenResponse, Uuid)> {
    let (access, refresh) = (new_token(), new_token());
    let refresh_id = Uuid::new_v4();
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
    let body = TokenResponse {
        access_token: access,
        token_type: "Bearer",
        expires_in: ACCESS_TTL_SECS,
        refresh_token: refresh,
        scope: SCOPE,
    };
    Ok((body, refresh_id))
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
