use std::sync::Arc;

use chrono::{DateTime, Utc};
use opsagent_core::oauth::{rules::is_loopback, ClientKind, ConsentRequest, OAuthClient};
use uuid::Uuid;

use crate::{
    actions::uow::UnitOfWork,
    error::{AppError, AppResult},
};

/// What the consent page shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentView {
    pub client_name: String,
    pub redirect_uri: String,
    /// Every client is dynamic or a metadata document: none is verified yet.
    pub verified: bool,
    /// Metadata-document clients: the host serving the document, the one fact about the
    /// client that is proven (its name is self-asserted). `None` for dynamic clients.
    pub publisher: Option<String>,
    pub loopback: bool,
    /// `(slug, name)` of the member's live organisations.
    pub organisations: Vec<(String, String)>,
}

/// An open consent request: `Gone("consent_expired")` once expired or decided.
pub(super) async fn open_request(
    uow: &dyn UnitOfWork,
    request_id: Uuid,
    now: DateTime<Utc>,
) -> AppResult<ConsentRequest> {
    uow.oauth()
        .consent(request_id)
        .await?
        .filter(|c| c.expires_at > now && c.code_hash.is_none())
        .ok_or(AppError::Gone("consent_expired"))
}

/// The host of a metadata-document client id (always an `https` URL); `None` for dynamic clients.
fn publisher(client: &OAuthClient) -> Option<String> {
    if client.kind != ClientKind::MetadataDocument {
        return None;
    }
    let rest = client.client_id.strip_prefix("https://")?;
    let host = rest.split(['/', '?', '#']).next()?.to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

pub struct GetConsent {
    uow: Arc<dyn UnitOfWork>,
}

impl GetConsent {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(
        &self,
        user_id: Uuid,
        request_id: Uuid,
        now: DateTime<Utc>,
    ) -> AppResult<ConsentView> {
        let request = open_request(self.uow.as_ref(), request_id, now).await?;
        let client = self
            .uow
            .oauth()
            .client(&request.client_id)
            .await?
            .ok_or(AppError::Gone("consent_expired"))?;
        let organisations = self
            .uow
            .orgs()
            .list_for_user(user_id)
            .await?
            .into_iter()
            .map(|(o, _)| (o.slug, o.name))
            .collect();
        Ok(ConsentView {
            publisher: publisher(&client),
            client_name: client.name,
            loopback: is_loopback(&request.redirect_uri),
            redirect_uri: request.redirect_uri,
            verified: false,
            organisations,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(id: &str, kind: ClientKind) -> OAuthClient {
        OAuthClient {
            client_id: id.into(),
            kind,
            name: "Codex".into(),
            redirect_uris: vec![],
            document_fetched_at: None,
            document_cache_until: None,
            last_used_at: None,
            expires_at: None,
        }
    }

    #[test]
    fn publisher_is_the_document_host_only_for_metadata_clients() {
        let doc = client(
            "https://ChatGPT.com/oauth/codex/client.json",
            ClientKind::MetadataDocument,
        );
        assert_eq!(publisher(&doc).as_deref(), Some("chatgpt.com"));
        let port = client(
            "https://a.example:8443/c.json",
            ClientKind::MetadataDocument,
        );
        assert_eq!(publisher(&port).as_deref(), Some("a.example:8443"));
        assert_eq!(publisher(&client("4f0c-dyn", ClientKind::Dynamic)), None);
    }
}
