use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use opsagent_core::oauth::{rules::redirect_uri_allowed, ClientKind, OAuthClient};
use serde_json::Value;

use crate::{
    actions::{uow::UnitOfWork, ClientMetadataSource},
    controllers::oauth::OAuthError,
};

/// A cached document is never trusted longer than this (mcp-contract, Clients).
const MAX_CACHE_SECS: u64 = 86_400;
/// Cache time for a document that sends no `max-age`.
const DEFAULT_CACHE_SECS: u64 = 3600;
const MAX_NAME_CHARS: usize = 100;

/// Finds the client a `client_id` names: a Client ID Metadata Document (an `https` URL,
/// fetched and cached) or a dynamically registered client.
#[derive(Clone)]
pub struct ResolveClient {
    uow: Arc<dyn UnitOfWork>,
    source: Arc<dyn ClientMetadataSource>,
}

fn internal(e: impl std::fmt::Display) -> OAuthError {
    tracing::error!(error = %e, "client lookup failed");
    OAuthError::server_error()
}

impl ResolveClient {
    pub fn new(uow: Arc<dyn UnitOfWork>, source: Arc<dyn ClientMetadataSource>) -> Self {
        Self { uow, source }
    }

    pub async fn run(
        &self,
        client_id: &str,
        now: DateTime<Utc>,
    ) -> Result<OAuthClient, OAuthError> {
        let mut client = if client_id.starts_with("https://") {
            self.document(client_id, now).await?
        } else {
            self.dynamic(client_id, now).await?
        };
        self.uow
            .oauth()
            .touch_client(client_id, now)
            .await
            .map_err(internal)?;
        client.last_used_at = Some(now);
        Ok(client)
    }

    async fn dynamic(
        &self,
        client_id: &str,
        now: DateTime<Utc>,
    ) -> Result<OAuthClient, OAuthError> {
        let repo = self.uow.oauth();
        let unknown = || OAuthError::invalid_client("Unknown client.");
        let client = repo
            .client(client_id)
            .await
            .map_err(internal)?
            .filter(|c| c.kind == ClientKind::Dynamic)
            .ok_or_else(unknown)?;
        if client.expires_at.is_some_and(|e| e < now)
            && !repo
                .client_has_live_grant(client_id)
                .await
                .map_err(internal)?
        {
            return Err(OAuthError::invalid_client(
                "The client registration expired.",
            ));
        }
        Ok(client)
    }

    async fn document(&self, url: &str, now: DateTime<Utc>) -> Result<OAuthClient, OAuthError> {
        let repo = self.uow.oauth();
        // `document_cache_until` is fetched_at + min(max-age, 24 h).
        if let Some(c) = repo.client(url).await.map_err(internal)? {
            if c.kind == ClientKind::MetadataDocument
                && c.document_cache_until.is_some_and(|e| e > now)
            {
                return Ok(c);
            }
        }
        let doc = self.source.fetch(url).await.map_err(|e| {
            tracing::warn!(error = %e, "client metadata fetch failed");
            OAuthError::invalid_client("The client metadata document could not be fetched.")
        })?;
        let ttl = doc
            .max_age_secs
            .unwrap_or(DEFAULT_CACHE_SECS)
            .min(MAX_CACHE_SECS);
        let client = parse(url, &doc.body, now, Duration::seconds(ttl as i64))?;
        repo.upsert_client(&client).await.map_err(internal)?;
        Ok(client)
    }
}

fn parse(
    url: &str,
    body: &Value,
    now: DateTime<Utc>,
    ttl: Duration,
) -> Result<OAuthClient, OAuthError> {
    let bad =
        |d: &str| OAuthError::invalid_client(format!("Invalid client metadata document: {d}"));
    if body.get("client_id").and_then(Value::as_str) != Some(url) {
        return Err(bad("client_id must equal the document URL."));
    }
    if body
        .get("token_endpoint_auth_method")
        .is_some_and(|m| m.as_str() != Some("none"))
    {
        return Err(bad(
            "only token_endpoint_auth_method \"none\" is supported.",
        ));
    }
    let uris: Vec<String> = body
        .get("redirect_uris")
        .and_then(Value::as_array)
        .and_then(|a| a.iter().map(|u| u.as_str().map(str::to_owned)).collect())
        .filter(|u: &Vec<String>| !u.is_empty() && u.len() <= 10)
        .ok_or_else(|| bad("redirect_uris must be 1 to 10 strings."))?;
    if !uris.iter().all(|u| redirect_uri_allowed(u)) {
        return Err(bad("a redirect URI is not allowed."));
    }
    let host = reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_else(|| url.to_owned());
    let name = body
        .get("client_name")
        .and_then(Value::as_str)
        .map(|n| n.trim().chars().take(MAX_NAME_CHARS).collect::<String>())
        .filter(|n| !n.is_empty())
        .unwrap_or(host);
    Ok(OAuthClient {
        client_id: url.to_owned(),
        kind: ClientKind::MetadataDocument,
        name,
        redirect_uris: uris,
        document_fetched_at: Some(now),
        document_cache_until: Some(now + ttl),
        last_used_at: None,
        expires_at: None,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use serde_json::json;

    use super::*;
    use crate::{
        actions::{uow::Repos, FetchedDocument, MetadataError},
        adapters::memory::MemStore,
    };

    const URL: &str = "https://app.example/client.json";

    struct Fake {
        body: Value,
        max_age: Option<u64>,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl ClientMetadataSource for Fake {
        async fn fetch(&self, _: &str) -> Result<FetchedDocument, MetadataError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(FetchedDocument {
                body: self.body.clone(),
                max_age_secs: self.max_age,
            })
        }
    }

    fn setup(body: Value, max_age: Option<u64>) -> (ResolveClient, Arc<Fake>, MemStore) {
        let fake = Arc::new(Fake {
            body,
            max_age,
            calls: AtomicUsize::new(0),
        });
        let store = MemStore::default();
        (
            ResolveClient::new(Arc::new(store.clone()), fake.clone()),
            fake,
            store,
        )
    }

    fn doc(id: &str) -> Value {
        json!({"client_id": id, "client_name": "Demo", "redirect_uris": ["https://app.example/cb"]})
    }

    fn calls(f: &Fake) -> usize {
        f.calls.load(Ordering::SeqCst)
    }

    #[tokio::test]
    async fn document_client_id_must_equal_url() {
        let (r, _, _) = setup(doc("https://evil.example/x.json"), None);
        let e = r.run(URL, Utc::now()).await.unwrap_err();
        assert_eq!(e.error, "invalid_client");
    }

    #[tokio::test]
    async fn stores_document_with_name_or_host() {
        let (r, _, _) = setup(doc(URL), None);
        let c = r.run(URL, Utc::now()).await.unwrap();
        assert_eq!(
            (c.kind, c.name.as_str()),
            (ClientKind::MetadataDocument, "Demo")
        );
        let (r, _, _) = setup(
            json!({"client_id": URL, "redirect_uris": ["https://app.example/cb"]}),
            None,
        );
        assert_eq!(r.run(URL, Utc::now()).await.unwrap().name, "app.example");
    }

    #[tokio::test]
    async fn cached_document_not_refetched_within_max_age() {
        let (r, fake, _) = setup(doc(URL), Some(600));
        let now = Utc::now();
        r.run(URL, now).await.unwrap();
        r.run(URL, now + Duration::seconds(599)).await.unwrap();
        assert_eq!(calls(&fake), 1);
        r.run(URL, now + Duration::seconds(601)).await.unwrap();
        assert_eq!(calls(&fake), 2);
    }

    #[tokio::test]
    async fn refetched_after_24h_even_if_max_age_longer() {
        let (r, fake, _) = setup(doc(URL), Some(7 * 86_400));
        let now = Utc::now();
        r.run(URL, now).await.unwrap();
        r.run(URL, now + Duration::hours(23)).await.unwrap();
        assert_eq!(calls(&fake), 1);
        r.run(URL, now + Duration::hours(25)).await.unwrap();
        assert_eq!(calls(&fake), 2);
    }

    #[tokio::test]
    async fn http_client_id_url_rejected() {
        let (r, fake, _) = setup(doc(URL), None);
        let e = r
            .run("http://app.example/client.json", Utc::now())
            .await
            .unwrap_err();
        assert_eq!(e.error, "invalid_client");
        assert_eq!(calls(&fake), 0);
    }

    fn dynamic(expires_in_days: i64, now: DateTime<Utc>) -> OAuthClient {
        OAuthClient {
            client_id: "dyn1".into(),
            kind: ClientKind::Dynamic,
            name: "n".into(),
            redirect_uris: vec!["https://a.example/cb".into()],
            document_fetched_at: None,
            document_cache_until: None,
            last_used_at: None,
            expires_at: Some(now + Duration::days(expires_in_days)),
        }
    }

    #[tokio::test]
    async fn dynamic_client_expired_without_grants_is_invalid() {
        let (r, _, store) = setup(doc(URL), None);
        let now = Utc::now();
        store
            .oauth()
            .upsert_client(&dynamic(-1, now))
            .await
            .unwrap();
        assert_eq!(
            r.run("dyn1", now).await.unwrap_err().error,
            "invalid_client"
        );
        store.oauth().upsert_client(&dynamic(1, now)).await.unwrap();
        assert!(r.run("dyn1", now).await.is_ok());
    }

    #[tokio::test]
    async fn dynamic_client_with_live_grant_never_expires() {
        use opsagent_core::oauth::Grant;
        use uuid::Uuid;
        let (r, _, store) = setup(doc(URL), None);
        let now = Utc::now();
        store
            .oauth()
            .upsert_client(&dynamic(-1, now))
            .await
            .unwrap();
        store
            .oauth()
            .insert_grant(&Grant {
                id: Uuid::new_v4(),
                client_id: "dyn1".into(),
                member_id: Uuid::new_v4(),
                organisation_id: Uuid::new_v4(),
                created_at: now,
                last_used_at: None,
                revoked_at: None,
            })
            .await
            .unwrap();
        assert!(r.run("dyn1", now).await.is_ok());
    }
}
