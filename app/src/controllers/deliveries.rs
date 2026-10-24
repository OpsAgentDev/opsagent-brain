//! Delivery history and the briefing preview. Recipient addresses and Slack tokens never leave
//! the server: a row shows its channel kind and, for email, the recipient's id.
use axum::{
    extract::{Path, State},
    Json,
};
use chrono::{DateTime, FixedOffset};
use opsagent_deliver::repo;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::{parse_id, OrgIdPath, OrgPath};
use crate::{
    actions::deliveries::DeliveryItem,
    api_error::{ApiError, ApiQuery, Problem},
    controllers::page::{page_request, Page, PageParams},
    middleware::org_scope::OrgScope,
    state::AppState,
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

fn view(
    DeliveryItem {
        row: d,
        recipient_id,
    }: DeliveryItem,
) -> Delivery {
    Delivery {
        recipient_id,
        id: d.id,
        connection_id: d.connection_id,
        kind: d.kind,
        channel: d.channel,
        status: d.status,
        attempts: d.attempts,
        sent_at: d.sent_at.map(|t| t.fixed_offset()),
        created_at: d.created_at.fixed_offset(),
    }
}

#[utoipa::path(get, path = "/orgs/{org}/deliveries", tag = "deliveries",
    params(OrgPath, DeliveryFilter, PageParams),
    responses((status = 200, body = Page<Delivery>), (status = 404, body = Problem), (status = 422, body = Problem)))]
async fn list(
    State(app): State<AppState>,
    scope: OrgScope,
    ApiQuery(f): ApiQuery<DeliveryFilter>,
    ApiQuery(p): ApiQuery<PageParams>,
) -> Result<Json<Page<Delivery>>, ApiError> {
    let connection = f
        .connection
        .map(|s| s.parse::<Uuid>().map_err(|_| bad("connection")))
        .transpose()?;
    if let Some(k) = &f.kind {
        if !KINDS.contains(&k.as_str()) {
            return Err(bad("kind"));
        }
    }
    let filter = repo::DeliveryFilter {
        connection_id: connection,
        kind: f.kind,
    };
    let list = &app.actions.deliveries.list_deliveries;
    let page = list
        .run(scope.organisation.id, filter, page_request(&p)?)
        .await?;
    Ok(Json(Page::of(page).map(view)))
}

#[utoipa::path(get, path = "/orgs/{org}/deliveries/{id}", tag = "deliveries", params(OrgIdPath),
    responses((status = 200, body = Delivery), (status = 404, body = Problem)))]
async fn show(
    State(app): State<AppState>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
) -> Result<Json<Delivery>, ApiError> {
    let get = &app.actions.deliveries.get_delivery;
    Ok(Json(view(
        get.run(scope.organisation.id, parse_id(&id)?).await?,
    )))
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
    State(app): State<AppState>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
) -> Result<Json<BriefingPreview>, ApiError> {
    let preview = &app.actions.deliveries.preview_briefing;
    let p = preview.run(scope.organisation.id, parse_id(&id)?).await?;
    Ok(Json(BriefingPreview {
        text: p.text,
        kind: p.kind.into(),
    }))
}

pub fn api() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list))
        .routes(routes!(show))
        .routes(routes!(preview))
}
