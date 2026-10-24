use std::{net::IpAddr, sync::Arc};

use chrono::{DateTime, Duration, Utc};
use opsagent_core::oauth::{
    rules::{redirect_uri_matches, resource_matches},
    ConsentRequest, SCOPE,
};
use serde::Deserialize;
use uuid::Uuid;

use super::{ResolveClient, CONSENT_TTL_SECS};
use crate::{
    actions::{ip_bucket, uow::UnitOfWork, RateLimiter, HOUR_SECS},
    controllers::oauth::OAuthError,
};

// Each authorize may fetch a client metadata document, so this also bounds outbound fetches.
const PER_IP_PER_HOUR: i64 = 120;
const MAX_STATE_CHARS: usize = 1024;

/// The `GET /oauth/authorize` query (RFC 6749 section 4.1.1, RFC 7636, RFC 8707).
#[derive(Debug, Default, Deserialize)]
pub struct AuthorizeParams {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub state: Option<String>,
    pub scope: Option<String>,
    pub resource: Option<String>,
}

#[derive(Debug)]
pub enum AuthorizeError {
    /// The client or redirect URI cannot be trusted: answer here, never redirect.
    NoRedirect(OAuthError),
    /// Sent back to the client's redirect URI with `error`, `state` and `iss`.
    Redirect {
        redirect_uri: String,
        error: &'static str,
        state: Option<String>,
    },
}

impl From<OAuthError> for AuthorizeError {
    fn from(e: OAuthError) -> Self {
        Self::NoRedirect(e)
    }
}

/// Validates an authorize request and stores it awaiting the member's consent.
pub struct StartAuthorization {
    uow: Arc<dyn UnitOfWork>,
    resolve: ResolveClient,
    limiter: Arc<dyn RateLimiter>,
    resource: String,
}

impl StartAuthorization {
    pub fn new(
        uow: Arc<dyn UnitOfWork>,
        resolve: ResolveClient,
        limiter: Arc<dyn RateLimiter>,
        resource: String,
    ) -> Self {
        Self {
            uow,
            resolve,
            limiter,
            resource,
        }
    }

    /// The consent request id.
    pub async fn run(
        &self,
        p: AuthorizeParams,
        client_ip: Option<IpAddr>,
        now: DateTime<Utc>,
    ) -> Result<Uuid, AuthorizeError> {
        self.limit(client_ip).await?;
        let client_id = p
            .client_id
            .ok_or_else(|| OAuthError::invalid_request("client_id is required."))?;
        let client = self.resolve.run(&client_id, now).await?;
        let redirect_uri = p
            .redirect_uri
            .filter(|r| {
                client
                    .redirect_uris
                    .iter()
                    .any(|reg| redirect_uri_matches(reg, r))
            })
            .ok_or_else(|| {
                OAuthError::invalid_request("redirect_uri is missing or not registered.")
            })?;
        let state = p.state;
        let fail = |error| AuthorizeError::Redirect {
            redirect_uri: redirect_uri.clone(),
            error,
            state: state.clone(),
        };
        if p.response_type.as_deref() != Some("code") {
            return Err(fail("unsupported_response_type"));
        }
        let challenge = p.code_challenge.filter(|c| s256_shape(c));
        let (Some(challenge), Some("S256")) = (challenge, p.code_challenge_method.as_deref())
        else {
            return Err(fail("invalid_request"));
        };
        if state.as_ref().is_some_and(|s| s.len() > MAX_STATE_CHARS) {
            return Err(fail("invalid_request"));
        }
        if p.scope
            .as_deref()
            .is_some_and(|s| !s.split_whitespace().all(|s| s == SCOPE))
        {
            return Err(fail("invalid_scope"));
        }
        if p.resource
            .as_deref()
            .is_some_and(|r| !resource_matches(&self.resource, r))
        {
            return Err(fail("invalid_target"));
        }
        let request = ConsentRequest {
            id: Uuid::new_v4(),
            client_id: client.client_id,
            redirect_uri: redirect_uri.clone(),
            code_challenge: challenge,
            state: state.clone(),
            resource: self.resource.clone(),
            scope: SCOPE.into(),
            member_id: None,
            organisation_id: None,
            code_hash: None,
            code_expires_at: None,
            code_used_at: None,
            grant_id: None,
            expires_at: now + Duration::seconds(CONSENT_TTL_SECS),
        };
        self.uow
            .oauth()
            .insert_consent(&request)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "consent request insert failed");
                OAuthError::server_error()
            })?;
        Ok(request.id)
    }

    /// Fails closed: a limiter outage is a 500, not an open door.
    async fn limit(&self, ip: Option<IpAddr>) -> Result<(), OAuthError> {
        // `unknown` only without X-Forwarded-For: behind Railway's edge ClientIp always has one.
        let who = ip.map_or_else(|| "unknown".to_owned(), |ip| ip_bucket(ip).to_string());
        let key = format!("oauth:authorize:ip:{who}");
        match self.limiter.hit(&key, PER_IP_PER_HOUR, HOUR_SECS).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(OAuthError::slow_down("Too many authorization requests.")),
            Err(e) => {
                tracing::error!(error = %e, "authorize rate limiter failed");
                Err(OAuthError::server_error())
            }
        }
    }
}

/// An S256 challenge is a base64url SHA-256: 43 characters, no padding.
fn s256_shape(c: &str) -> bool {
    c.len() == 43
        && c.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
