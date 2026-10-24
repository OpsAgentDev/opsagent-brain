use std::{net::IpAddr, sync::Arc};

use chrono::Duration;
use opsagent_core::{
    oauth::{rules::redirect_uri_allowed, ClientKind, OAuthClient},
    repo::Clock,
};
use serde::Deserialize;

use crate::{
    actions::{uow::UnitOfWork, RateLimiter, DAY_SECS, HOUR_SECS},
    controllers::oauth::OAuthError,
    tokens::new_token,
};

const PER_IP_PER_HOUR: i64 = 60;
const GLOBAL_PER_DAY: i64 = 2000;
/// A dynamic client expires after 90 days unused (never while it has a live grant).
const CLIENT_TTL_DAYS: i64 = 90;
const MAX_REDIRECT_URIS: usize = 10;
const MAX_NAME_CHARS: usize = 100;

/// The RFC 7591 fields brain honours; the rest of the body is ignored.
#[derive(Debug, Deserialize)]
pub struct RegistrationRequest {
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    pub client_name: Option<String>,
    pub token_endpoint_auth_method: Option<String>,
    pub grant_types: Option<Vec<String>>,
}

/// Dynamic client registration (public clients only).
pub struct RegisterClient {
    uow: Arc<dyn UnitOfWork>,
    limiter: Arc<dyn RateLimiter>,
    clock: Arc<dyn Clock>,
}

impl RegisterClient {
    pub fn new(
        uow: Arc<dyn UnitOfWork>,
        limiter: Arc<dyn RateLimiter>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            uow,
            limiter,
            clock,
        }
    }

    pub async fn run(
        &self,
        req: RegistrationRequest,
        client_ip: IpAddr,
    ) -> Result<OAuthClient, OAuthError> {
        validate(&req)?;
        self.limit(client_ip).await?;
        let now = self.clock.now();
        let name = req
            .client_name
            .map(|n| n.trim().chars().take(MAX_NAME_CHARS).collect::<String>())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| "Unnamed client".into());
        let client = OAuthClient {
            client_id: new_token(),
            kind: ClientKind::Dynamic,
            name,
            redirect_uris: req.redirect_uris,
            document_fetched_at: None,
            last_used_at: None,
            expires_at: Some(now + Duration::days(CLIENT_TTL_DAYS)),
        };
        self.uow.oauth().upsert_client(&client).await.map_err(|e| {
            tracing::error!(error = %e, "client registration failed");
            OAuthError::server_error()
        })?;
        Ok(client)
    }

    /// Fails closed: a limiter outage is a 500, not an open door.
    async fn limit(&self, ip: IpAddr) -> Result<(), OAuthError> {
        for (key, cap, window) in [
            (
                format!("oauth:register:ip:{ip}"),
                PER_IP_PER_HOUR,
                HOUR_SECS,
            ),
            ("oauth:register:global".to_owned(), GLOBAL_PER_DAY, DAY_SECS),
        ] {
            match self.limiter.hit(&key, cap, window).await {
                Ok(true) => {}
                Ok(false) => return Err(OAuthError::slow_down("Too many registrations.")),
                Err(e) => {
                    tracing::error!(error = %e, "registration rate limiter failed");
                    return Err(OAuthError::server_error());
                }
            }
        }
        Ok(())
    }
}

fn validate(req: &RegistrationRequest) -> Result<(), OAuthError> {
    if req.redirect_uris.is_empty() || req.redirect_uris.len() > MAX_REDIRECT_URIS {
        return Err(OAuthError::invalid_redirect_uri(
            "Provide between 1 and 10 redirect_uris.",
        ));
    }
    if let Some(bad) = req.redirect_uris.iter().find(|u| !redirect_uri_allowed(u)) {
        return Err(OAuthError::invalid_redirect_uri(format!(
            "redirect_uri not allowed: {}",
            bad.chars().take(200).collect::<String>()
        )));
    }
    if req
        .token_endpoint_auth_method
        .as_deref()
        .is_some_and(|m| m != "none")
    {
        return Err(OAuthError::invalid_client_metadata(
            "Only token_endpoint_auth_method \"none\" is supported.",
        ));
    }
    if let Some(g) = &req.grant_types {
        if g.iter()
            .any(|g| !matches!(g.as_str(), "authorization_code" | "refresh_token"))
        {
            return Err(OAuthError::invalid_client_metadata(
                "Only authorization_code and refresh_token grants are supported.",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::memory::{FixedClock, MemRateLimiter, MemStore};

    fn action() -> RegisterClient {
        RegisterClient::new(
            Arc::new(MemStore::default()),
            Arc::new(MemRateLimiter::default()),
            Arc::new(FixedClock(chrono::Utc::now())),
        )
    }

    fn req(uris: &[&str]) -> RegistrationRequest {
        RegistrationRequest {
            redirect_uris: uris.iter().map(|s| (*s).into()).collect(),
            client_name: None,
            token_endpoint_auth_method: None,
            grant_types: None,
        }
    }

    const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7));

    #[tokio::test]
    async fn registers_a_dynamic_client_expiring_in_90_days() {
        let c = action()
            .run(req(&["https://a.example/cb"]), IP)
            .await
            .unwrap();
        assert_eq!(c.kind, ClientKind::Dynamic);
        assert!(c.expires_at.is_some());
    }

    #[tokio::test]
    async fn rejects_bad_metadata() {
        let a = action();
        let e = a.run(req(&["javascript:alert(1)"]), IP).await.unwrap_err();
        assert_eq!(e.error, "invalid_redirect_uri");
        let mut r = req(&["https://a.example/cb"]);
        r.token_endpoint_auth_method = Some("client_secret_basic".into());
        assert_eq!(
            a.run(r, IP).await.unwrap_err().error,
            "invalid_client_metadata"
        );
        let mut r = req(&["https://a.example/cb"]);
        r.grant_types = Some(vec!["password".into()]);
        assert_eq!(
            a.run(r, IP).await.unwrap_err().error,
            "invalid_client_metadata"
        );
        assert_eq!(
            a.run(req(&[]), IP).await.unwrap_err().error,
            "invalid_redirect_uri"
        );
    }
}
