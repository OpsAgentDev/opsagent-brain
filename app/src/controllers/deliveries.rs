//! Delivery history and the briefing preview. Recipient addresses and Slack tokens never leave
//! the server: a row shows its channel kind and, for email, the recipient's id.
use crate::adapters::db::ledger_storage::stmt;
use std::collections::HashMap;

use axum::{
    extract::{Path, State},
    Json,
};
use chrono::{DateTime, FixedOffset, Utc};
use loco_rs::app::AppContext;
use opsagent_deliver::{model::Briefing, render_text};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryTrait, Statement, TryGetable,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::{OrgIdPath, OrgPath};
use crate::{
    api_error::{ApiError, ApiQuery, Problem},
    middleware::org_scope::OrgScope,
    models::{
        _entities::{connections, deliveries},
        find_in_org,
    },
    services::{
        deliveries::{briefing, deliverable},
        pagination::{self, Page, PageParams},
    },
    settings::Settings,
};

const KINDS: [&str; 4] = ["briefing", "weekly", "alert", "notice"];

#[derive(Serialize, ToSchema)]
pub struct Delivery {
    pub id: Uuid,
    pub connection_id: Option<Uuid>,
    /// `briefing`, `weekly`, `alert` or `notice`.
    pub kind: String,
    /// `slack` or `email`.
    pub channel: String,
    /// The email recipient (or owner) the row went to; null for Slack and unknown addresses.
    pub recipient_id: Option<Uuid>,
    /// `pending`, `sent`, `failed`, `skipped`, `fallback_email` or `suppressed`.
    pub status: String,
    pub attempts: i32,
    pub sent_at: Option<DateTime<FixedOffset>>,
    pub created_at: DateTime<FixedOffset>,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct DeliveryFilter {
    /// Connection id.
    pub connection: Option<String>,
    /// `briefing`, `weekly`, `alert` or `notice`.
    pub kind: Option<String>,
}

fn bad(what: &str) -> ApiError {
    ApiError::invalid(format!("{what} is not valid"))
}

/// Email address (lowercased) to the id of its `recipients` row in this org (oldest wins). Owner
/// fallback sends have no row, so they map to nothing.
async fn recipient_ids(
    ctx: &AppContext,
    org: Uuid,
    rows: &[deliveries::Model],
) -> Result<HashMap<String, Uuid>, ApiError> {
    let emails: Vec<String> = rows
        .iter()
        .filter(|d| d.channel == "email")
        .map(|d| d.target.to_lowercase())
        .collect();
    if emails.is_empty() {
        return Ok(HashMap::new());
    }
    let q: Statement = stmt(
        "SELECT DISTINCT ON (lower(email)) lower(email) AS email, id FROM recipients \
         WHERE organisation_id = $1 AND lower(email) = ANY($2) \
         ORDER BY lower(email), created_at, id",
        vec![org.into(), emails.into()],
    );
    let mut map = HashMap::new();
    for r in ctx.db.query_all_raw(q).await? {
        let email = String::try_get(&r, "", "email").map_err(sea_orm::DbErr::from)?;
        let id = Uuid::try_get(&r, "", "id").map_err(sea_orm::DbErr::from)?;
        map.insert(email, id);
    }
    Ok(map)
}

fn view(d: deliveries::Model, ids: &HashMap<String, Uuid>) -> Delivery {
    Delivery {
        recipient_id: (d.channel == "email")
            .then(|| ids.get(&d.target.to_lowercase()).copied())
            .flatten(),
        id: d.id,
        connection_id: d.connection_id,
        kind: d.kind,
        channel: d.channel,
        status: d.status,
        attempts: d.attempts,
        sent_at: d.sent_at,
        created_at: d.created_at,
    }
}

#[utoipa::path(get, path = "/orgs/{org}/deliveries", tag = "deliveries",
    params(OrgPath, DeliveryFilter, PageParams),
    responses((status = 200, body = Page<Delivery>), (status = 404, body = Problem), (status = 422, body = Problem)))]
async fn list(
    State(ctx): State<AppContext>,
    scope: OrgScope,
    ApiQuery(f): ApiQuery<DeliveryFilter>,
    ApiQuery(p): ApiQuery<PageParams>,
) -> Result<Json<Page<Delivery>>, ApiError> {
    use deliveries::Column as C;
    let connection = f
        .connection
        .map(|s| s.parse::<Uuid>().map_err(|_| bad("connection")))
        .transpose()?;
    if let Some(k) = &f.kind {
        if !KINDS.contains(&k.as_str()) {
            return Err(bad("kind"));
        }
    }
    let q = deliveries::Entity::find()
        .filter(C::OrganisationId.eq(scope.organisation_id))
        .apply_if(connection, |q, v| q.filter(C::ConnectionId.eq(v)))
        .apply_if(f.kind, |q, v| q.filter(C::Kind.eq(v)));
    let page = pagination::fetch(
        &ctx.db,
        q,
        (C::CreatedAt, C::Id),
        |m| (m.created_at, m.id),
        &p,
    )
    .await?;
    let ids = recipient_ids(&ctx, scope.organisation_id, &page.items).await?;
    Ok(Json(page.map(|d| view(d, &ids))))
}

#[utoipa::path(get, path = "/orgs/{org}/deliveries/{id}", tag = "deliveries", params(OrgIdPath),
    responses((status = 200, body = Delivery), (status = 404, body = Problem)))]
async fn show(
    State(ctx): State<AppContext>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
) -> Result<Json<Delivery>, ApiError> {
    let col = deliveries::Column::OrganisationId;
    let d = find_in_org::<deliveries::Entity>(&ctx.db, col, scope.organisation_id, &id).await?;
    let ids = recipient_ids(&ctx, scope.organisation_id, std::slice::from_ref(&d)).await?;
    Ok(Json(view(d, &ids)))
}

#[derive(Serialize, ToSchema)]
pub struct BriefingPreview {
    /// Exactly what `deliver_briefing` would send now; empty for `none`.
    pub text: String,
    /// `first_scan`, `daily`, or `none` when there is nothing to say.
    pub kind: String,
}

#[utoipa::path(post, path = "/orgs/{org}/connections/{id}/briefing/preview", tag = "deliveries",
    params(OrgIdPath),
    responses((status = 200, body = BriefingPreview), (status = 404, body = Problem)))]
async fn preview(
    State(ctx): State<AppContext>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
) -> Result<Json<BriefingPreview>, ApiError> {
    let col = connections::Column::OrganisationId;
    let c = find_in_org::<connections::Entity>(&ctx.db, col, scope.organisation_id, &id).await?;
    let now = Utc::now();
    let b = if deliverable(&c) {
        briefing(&ctx.db, &c, now, now, &Settings::get(&ctx).web_base_url).await?
    } else {
        None
    };
    let kind = match &b {
        Some(Briefing::FirstScan { .. }) => "first_scan",
        Some(Briefing::Daily { .. }) => "daily",
        None => "none",
    };
    Ok(Json(BriefingPreview {
        text: b.as_ref().map(render_text).unwrap_or_default(),
        kind: kind.into(),
    }))
}

pub fn api() -> OpenApiRouter<AppContext> {
    OpenApiRouter::new()
        .routes(routes!(list))
        .routes(routes!(show))
        .routes(routes!(preview))
}
