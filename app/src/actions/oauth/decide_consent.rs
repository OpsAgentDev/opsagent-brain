use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use opsagent_core::{audit::AuditEntry, repo::RepoError};
use uuid::Uuid;

use super::{get_consent::open_request, redirect_with, CODE_TTL_SECS};
use crate::{
    actions::{orgs::ResolveOrgScope, uow::UnitOfWork},
    error::{AppError, AppResult},
    tokens::{hash_token, new_token},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Approve for the organisation with this slug.
    Approve(String),
    Deny,
}

/// The member's answer on the consent page; returns where the browser goes next.
pub struct DecideConsent {
    uow: Arc<dyn UnitOfWork>,
    scope: ResolveOrgScope,
    issuer: String,
}

impl DecideConsent {
    pub fn new(uow: Arc<dyn UnitOfWork>, issuer: String) -> Self {
        Self {
            scope: ResolveOrgScope::new(uow.clone()),
            uow,
            issuer,
        }
    }

    pub async fn run(
        &self,
        user_id: Uuid,
        request_id: Uuid,
        decision: Decision,
        now: DateTime<Utc>,
    ) -> AppResult<String> {
        let request = open_request(self.uow.as_ref(), request_id, now).await?;
        let state = request.state.as_deref();
        let iss = self.issuer.as_str();
        let target = Some(("oauth_client", request.client_id.clone()));
        let slug = match decision {
            Decision::Deny => {
                let tx = self.uow.begin().await?;
                gone_if_missing(tx.oauth().close_consent(request_id, now).await)?;
                let entry = AuditEntry::member(None, user_id, "oauth.consent.denied", target);
                tx.audit().record(entry).await?;
                tx.commit().await?;
                let pairs = [("error", Some("access_denied")), ("state", state)];
                return Ok(redirect_with(&request.redirect_uri, &pairs, iss));
            }
            Decision::Approve(slug) => slug,
        };
        let scope = self.scope.run(user_id, &slug).await?;
        let org_id = scope.organisation.id;
        let code = new_token();
        let tx = self.uow.begin().await?;
        let expires = now + Duration::seconds(CODE_TTL_SECS);
        let code_hash = hash_token(&code);
        let decided = tx
            .oauth()
            .decide_consent(
                request_id,
                scope.member.id,
                org_id,
                &code_hash,
                expires,
                now,
            )
            .await;
        gone_if_missing(decided)?;
        let entry = AuditEntry::member(Some(org_id), user_id, "oauth.consent.approved", target);
        tx.audit().record(entry).await?;
        tx.commit().await?;
        let pairs = [("code", Some(code.as_str())), ("state", state)];
        Ok(redirect_with(&request.redirect_uri, &pairs, iss))
    }
}

/// A request decided or expired since it was read is `Gone`, like one found that way.
fn gone_if_missing(r: Result<(), RepoError>) -> AppResult<()> {
    match r {
        Err(RepoError::NotFound) => Err(AppError::Gone("consent_expired")),
        other => Ok(other?),
    }
}
