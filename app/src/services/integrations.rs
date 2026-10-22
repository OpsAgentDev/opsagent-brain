//! Integration use cases: Slack install (OAuth), channel listing, removal.
use axum::http::StatusCode;
use opsagent_secrets::Kek;
use sea_orm::{
    sea_query::OnConflict, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder,
    Set, TransactionTrait,
};
use serde_json::json;
use uuid::Uuid;

use crate::{
    adapters::slack::{Channel, Install, SlackClient, SlackError, AUTHORIZE_URL, BOT_SCOPES},
    api_error::ApiError,
    models::{
        _entities::integrations::{self, Column as C},
        audit,
        integrations::{open_token, seal_token, ACTIVE, REVOKED, SLACK},
        now,
    },
    settings::Settings,
};

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
pub async fn save_slack(
    db: &DatabaseConnection,
    kek: &dyn Kek,
    organisation_id: Uuid,
    actor: Uuid,
    install: &Install,
) -> Result<(), ApiError> {
    let (sealed, kek_version) = seal_token(db, kek, organisation_id, &install.access_token).await?;
    let row = integrations::ActiveModel {
        id: Set(Uuid::new_v4()),
        organisation_id: Set(organisation_id),
        kind: Set(SLACK.into()),
        config: Set(json!({
            "team_id": install.team_id, "team_name": install.team_name,
            "bot_user_id": install.bot_user_id, "scope": install.scope,
        })),
        ciphertext: Set(sealed.ciphertext),
        nonce: Set(sealed.nonce.to_vec()),
        kek_version: Set(kek_version),
        status: Set(ACTIVE.into()),
        created_at: Set(now()),
        updated_at: Set(now()),
    };
    let upsert = OnConflict::columns([C::OrganisationId, C::Kind])
        .update_columns([C::Config, C::Ciphertext, C::Nonce, C::KekVersion, C::Status])
        .value(C::UpdatedAt, now())
        .to_owned();
    let txn = db.begin().await?;
    integrations::Entity::insert(row)
        .on_conflict(upsert)
        .exec_without_returning(&txn)
        .await?;
    audit::record(
        &txn,
        Some(organisation_id),
        actor,
        "integration.slack_connect",
        Some(("integration", SLACK.into())),
    )
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
    let row = integrations::Entity::find()
        .filter(C::OrganisationId.eq(organisation_id))
        .filter(C::Kind.eq(SLACK))
        .one(db)
        .await?
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
            integrations::Entity::update_many()
                .col_expr(C::Status, REVOKED.into())
                .col_expr(C::UpdatedAt, now().into())
                .filter(C::OrganisationId.eq(organisation_id))
                .filter(C::Id.eq(row.id))
                .exec(db)
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
) -> Result<Vec<integrations::Model>, ApiError> {
    Ok(integrations::Entity::find()
        .filter(C::OrganisationId.eq(organisation_id))
        .order_by_asc(C::CreatedAt)
        .all(db)
        .await?)
}

/// Removes integration `id` and its sealed token, for owner `actor`.
pub async fn delete(
    db: &DatabaseConnection,
    organisation_id: Uuid,
    actor: Uuid,
    id: Uuid,
) -> Result<(), ApiError> {
    let txn = db.begin().await?;
    let gone = integrations::Entity::delete_many()
        .filter(C::OrganisationId.eq(organisation_id))
        .filter(C::Id.eq(id))
        .exec(&txn)
        .await?;
    if gone.rows_affected != 1 {
        return Err(ApiError::not_found());
    }
    audit::record(
        &txn,
        Some(organisation_id),
        actor,
        "integration.delete",
        Some(("integration", id.to_string())),
    )
    .await?;
    txn.commit().await?;
    Ok(())
}
