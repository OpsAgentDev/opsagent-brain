use std::sync::Arc;

use chrono::{DateTime, Utc};
use opsagent_core::{
    audit::AuditEntry,
    oauth::{
        rules::{pkce_s256_matches, resource_matches},
        Grant,
    },
};
use uuid::Uuid;

use super::{internal, live_member, mint, revoke_audited, TokenResponse};
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

fn bad() -> OAuthError {
    OAuthError::invalid_grant("The code is invalid, expired or already used.")
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
        let code_hash = hash_token(&x.code);
        // Consumed inside the grant's transaction: a concurrent replay waits on the row lock,
        // then finds the code used with its grant recorded, and revokes it.
        let tx = self.uow.begin().await.map_err(internal)?;
        let Some(c) = tx
            .oauth()
            .consume_code(&code_hash, now)
            .await
            .map_err(internal)?
        else {
            drop(tx);
            self.revoke_replayed(&code_hash, now).await?;
            return Err(bad());
        };
        // A failed check still commits the consumption, so a wrong guess burns the code.
        let member = match (c.member_id, c.organisation_id) {
            (Some(m), Some(o)) => live_member(tx.as_ref(), o, m).await.map_err(internal)?,
            _ => None,
        };
        let valid = c.client_id == x.client_id
            // Exact: the loopback port leniency applies at authorize only (RFC 6749 4.1.3).
            && c.redirect_uri == x.redirect_uri
            && x.resource
                .as_deref()
                .is_none_or(|r| resource_matches(&c.resource, r))
            && pkce_s256_matches(&c.code_challenge, &x.code_verifier);
        let (Some(member), true) = (member, valid) else {
            tx.commit().await.map_err(internal)?;
            return Err(bad());
        };
        let grant = Grant {
            id: Uuid::new_v4(),
            client_id: c.client_id,
            member_id: member.id,
            organisation_id: member.organisation_id,
            created_at: now,
            last_used_at: None,
            revoked_at: None,
        };
        tx.oauth().insert_grant(&grant).await.map_err(internal)?;
        let tokens = mint(tx.as_ref(), &grant, Uuid::new_v4(), now)
            .await
            .map_err(internal)?;
        tx.oauth()
            .set_consent_grant(c.id, grant.id)
            .await
            .map_err(internal)?;
        let target = Some(("oauth_grant", grant.id.to_string()));
        let entry = AuditEntry::member(
            Some(grant.organisation_id),
            member.user_id,
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
        let tx = self.uow.begin().await.map_err(internal)?;
        let used = tx
            .oauth()
            .consent_by_code_hash(code_hash)
            .await
            .map_err(internal)?
            .filter(|c| c.code_used_at.is_some());
        if let Some(c) = used {
            if let (Some(org), Some(grant), Some(member)) =
                (c.organisation_id, c.grant_id, c.member_id)
            {
                revoke_audited(tx.as_ref(), org, grant, member, "code_replay", now)
                    .await
                    .map_err(internal)?;
            }
        }
        tx.commit().await.map_err(internal)
    }
}
