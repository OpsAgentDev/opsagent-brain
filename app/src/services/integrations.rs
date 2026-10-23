//! Integration use cases: Slack install (OAuth), channel listing, removal. Tokens are sealed
//! with the org DEK (AAD table `integrations`, column `ciphertext`).
use axum::http::StatusCode;
use chrono::Utc;
use loco_rs::Error;
use opsagent_core::{
    audit::{AuditEntry, AuditLog},
    repo::RepoError,
};
use opsagent_deliver::repo::{Integration, IntegrationsRepo, SealedToken, REVOKED, SLACK};
use opsagent_secrets::{open, seal, Aad, Kek, Sealed};
use sea_orm::{ConnectionTrait, DatabaseConnection, TransactionTrait};
use serde_json::json;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    actions::uow::Repos,
    adapters::db::Pg,
    adapters::slack::{Channel, Install, SlackClient, SlackError, AUTHORIZE_URL, BOT_SCOPES},
    api_error::ApiError,
    models::connections::org_dek,
    settings::Settings,
};

fn aad(organisation_id: Uuid) -> Aad {
    Aad {
        organisation_id,
        table: "integrations",
        column: "ciphertext",
    }
}

/// `token` sealed under the org DEK, with the KEK version to store beside it.
async fn seal_token(
    db: &impl ConnectionTrait,
    kek: &dyn Kek,
    organisation_id: Uuid,
    token: &str,
) -> loco_rs::Result<SealedToken> {
    let dek = org_dek(db, kek, organisation_id).await?;
    let sealed = seal(&dek.key, token.as_bytes(), &aad(organisation_id));
    Ok(SealedToken {
        ciphertext: sealed.ciphertext,
        nonce: sealed.nonce.to_vec(),
        kek_version: dek.version,
    })
}

/// The integration's plaintext token.
pub async fn open_token(
    db: &impl ConnectionTrait,
    kek: &dyn Kek,
    row: &Integration,
) -> loco_rs::Result<Zeroizing<String>> {
    let dek = org_dek(db, kek, row.organisation_id).await?;
    let sealed = Sealed {
        ciphertext: row.ciphertext.clone(),
        nonce: row
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| Error::string("bad integration nonce"))?,
    };
    let plain = open(&dek.key, &sealed, &aad(row.organisation_id))
        .map_err(|e| Error::string(&e.to_string()))?;
    String::from_utf8(plain.to_vec())
        .map(Zeroizing::new)
        .map_err(|_| Error::string("integration token is not UTF-8"))
}

/// Another organisation already holds this Slack workspace (one workspace, one organisation).
pub const WORKSPACE_IN_USE: &str = "slack_workspace_in_use";

pub fn slack_redirect_uri(s: &Settings) -> String {
    format!(
        "{}/v1/integrations/slack/callback",
        s.api_base_url.trim_end_matches('/')
    )
}

/// The Slack consent URL for `state`; 503 `slack_not_configured` without a client id.
pub fn slack_authorize_url(s: &Settings, state: &str) -> Result<String, ApiError> {
    if s.slack_client_id.is_empty() || s.slack_client_secret.is_empty() {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "slack_not_configured",
            "Slack is not configured.",
        ));
    }
    let e = |v: &str| urlencoding::encode(v).into_owned();
    Ok(format!(
        "{AUTHORIZE_URL}?client_id={}&scope={}&redirect_uri={}&state={}",
        e(&s.slack_client_id),
        e(BOT_SCOPES),
        e(&slack_redirect_uri(s)),
        e(state)
    ))
}

/// Seals the bot token and makes it the org's active Slack integration (a reinstall replaces it).
/// 409 `slack_workspace_in_use` when another organisation's active integration has the team.
pub async fn save_slack(
    db: &DatabaseConnection,
    kek: &dyn Kek,
    organisation_id: Uuid,
    actor: Uuid,
    install: &Install,
) -> Result<(), ApiError> {
    let token = seal_token(db, kek, organisation_id, &install.access_token).await?;
    let config = json!({
        "team_id": install.team_id, "team_name": install.team_name,
        "bot_user_id": install.bot_user_id, "scope": install.scope,
    });
    let txn = db.begin().await?;
    Pg::new(&txn)
        .upsert_slack(organisation_id, config, token)
        .await
        .map_err(|e| match e {
            RepoError::Conflict(_) => ApiError::new(
                StatusCode::CONFLICT,
                WORKSPACE_IN_USE,
                "This Slack workspace is linked to another organisation.",
            ),
            e => e.into(),
        })?;
    Pg::new(&txn)
        .record(AuditEntry::member(
            Some(organisation_id),
            actor,
            "integration.slack_connect",
            Some(("integration", SLACK.into())),
        ))
        .await?;
    txn.commit().await?;
    Ok(())
}

fn slack_unavailable(code: &'static str, detail: &str) -> ApiError {
    ApiError::new(StatusCode::SERVICE_UNAVAILABLE, code, detail)
}

/// Channels the bot can post to. A revoked token marks the integration `revoked`.
pub async fn slack_channels(
    db: &DatabaseConnection,
    kek: &dyn Kek,
    slack: &dyn SlackClient,
    organisation_id: Uuid,
) -> Result<Vec<Channel>, ApiError> {
    let repo = Pg::new(db);
    let row = repo
        .integrations()
        .list(organisation_id)
        .await?
        .into_iter()
        .find(|i| i.kind == SLACK)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "slack_not_connected",
                "Slack is not connected.",
            )
        })?;
    let revoked = || {
        slack_unavailable(
            "slack_revoked",
            "Slack access was revoked; reconnect Slack.",
        )
    };
    if row.status == REVOKED {
        return Err(revoked());
    }
    let token = open_token(db, kek, &row).await?;
    match slack.channels(&token).await {
        Ok(c) => Ok(c),
        Err(SlackError::Revoked) => {
            repo.mark_revoked(organisation_id, row.id, Utc::now())
                .await?;
            Err(revoked())
        }
        Err(SlackError::RateLimited(s)) => Err(ApiError::rate_limited(
            "Slack is rate limiting; retry later.",
            s,
        )),
        Err(e) => {
            tracing::warn!(error_code = e.code(), "slack channel list failed");
            Err(ApiError::new(
                StatusCode::BAD_GATEWAY,
                "slack_error",
                "Slack did not answer as expected.",
            ))
        }
    }
}

pub async fn list(
    db: &DatabaseConnection,
    organisation_id: Uuid,
) -> Result<Vec<Integration>, ApiError> {
    Ok(Pg::new(db).integrations().list(organisation_id).await?)
}

/// Removes integration `id` for owner `actor`, then revokes its token at Slack (best effort).
pub async fn delete(
    db: &DatabaseConnection,
    kek: &dyn Kek,
    slack: &dyn SlackClient,
    organisation_id: Uuid,
    actor: Uuid,
    id: Uuid,
) -> Result<(), ApiError> {
    let row = Pg::new(db)
        .integrations()
        .list(organisation_id)
        .await?
        .into_iter()
        .find(|i| i.id == id)
        .ok_or_else(ApiError::not_found)?;
    // Opened before the row (and its sealed token) is gone.
    let token = open_token(db, kek, &row).await;
    let txn = db.begin().await?;
    let repo = Pg::new(&txn);
    if !repo.integrations().delete(organisation_id, id).await? {
        return Err(ApiError::not_found());
    }
    repo.record(AuditEntry::member(
        Some(organisation_id),
        actor,
        "integration.delete",
        Some(("integration", id.to_string())),
    ))
    .await?;
    txn.commit().await?;
    match (row.kind.as_str(), token) {
        (SLACK, Ok(t)) => {
            if let Err(e) = slack.revoke(&t).await {
                tracing::warn!(error_code = e.code(), "slack token revoke failed");
            }
        }
        (SLACK, Err(_)) => tracing::warn!(
            error_code = "token_unreadable",
            "slack token revoke skipped"
        ),
        _ => {}
    }
    Ok(())
}
