use std::sync::Arc;

use chrono::{DateTime, Utc};
use opsagent_core::oauth::{rules::is_loopback, ConsentRequest};
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
            client_name: client.name,
            loopback: is_loopback(&request.redirect_uri),
            redirect_uri: request.redirect_uri,
            verified: false,
            organisations,
        })
    }
}
