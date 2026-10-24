use std::sync::Arc;

use chrono::{DateTime, Utc};
use opsagent_core::{
    audit::AuditEntry,
    oauth::{
        rules::{pkce_s256_matches, redirect_uri_matches, resource_matches},
        Grant,
    },
};
use uuid::Uuid;

use super::{internal, mint, TokenResponse};
use crate::{actions::uow::UnitOfWork, controllers::oauth::OAuthError, tokens::hash_token};

/// What the client sends with `grant_type=authorization_code`.
pub struct CodeExchange {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_verifier: String,
    pub resource: Option<String>,
}

/// `authorization_code`: spends the code once and issues the grant's first tokens.
pub struct ExchangeCode {
    uow: Arc<dyn UnitOfWork>,
}

impl ExchangeCode {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(
        &self,
        x: CodeExchange,
        now: DateTime<Utc>,
    ) -> Result<TokenResponse, OAuthError> {
        let bad = || OAuthError::invalid_grant("The code is invalid, expired or already used.");
        let code_hash = hash_token(&x.code);
        let repo = self.uow.oauth();
        let Some(c) = repo.consume_code(&code_hash, now).await.map_err(internal)? else {
            self.revoke_replayed(&code_hash, now).await?;
            return Err(bad());
        };
        let (Some(member_id), Some(organisation_id)) = (c.member_id, c.organisation_id) else {
            return Err(bad());
        };
        // The code is spent before these checks, so a wrong guess burns it.
        if c.client_id != x.client_id
            || !redirect_uri_matches(&c.redirect_uri, &x.redirect_uri)
            || x.resource
                .as_deref()
                .is_some_and(|r| !resource_matches(&c.resource, r))
            || !pkce_s256_matches(&c.code_challenge, &x.code_verifier)
        {
            return Err(bad());
        }
        let grant = Grant {
            id: Uuid::new_v4(),
            client_id: c.client_id,
            member_id,
            organisation_id,
            created_at: now,
            last_used_at: None,
            revoked_at: None,
        };
        let tx = self.uow.begin().await.map_err(internal)?;
        tx.oauth().insert_grant(&grant).await.map_err(internal)?;
        let (tokens, _) = mint(tx.as_ref(), &grant, now).await.map_err(internal)?;
        tx.oauth()
            .set_consent_grant(c.id, grant.id)
            .await
            .map_err(internal)?;
        let target = Some(("oauth_grant", grant.id.to_string()));
        let entry = AuditEntry::member(
            Some(organisation_id),
            member_id,
            "oauth.token.issued",
            target,
        )
        .with_meta(serde_json::json!({"client_id": grant.client_id}));
        tx.audit().record(entry).await.map_err(internal)?;
        tx.commit().await.map_err(internal)?;
        Ok(tokens)
    }

    /// A used code presented again: revoke everything issued from it (RFC 6749 section 4.1.2).
    async fn revoke_replayed(&self, code_hash: &str, now: DateTime<Utc>) -> Result<(), OAuthError> {
        let repo = self.uow.oauth();
        let used = repo
            .consent_by_code_hash(code_hash)
            .await
            .map_err(internal)?;
        if let Some(c) = used.filter(|c| c.code_used_at.is_some()) {
            if let (Some(org), Some(grant)) = (c.organisation_id, c.grant_id) {
                tracing::warn!(grant_id = %grant, "authorization code replayed; grant revoked");
                repo.revoke_grant(org, grant, now).await.map_err(internal)?;
            }
        }
        Ok(())
    }
}
