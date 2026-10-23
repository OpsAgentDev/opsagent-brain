use axum::{extract::State, Json};
use chrono::{DateTime, FixedOffset};
use opsagent_core::resource::{self as core, ResourceKind, ResourceRow};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::page::{page_request, Page, PageParams};
use crate::{
    api_error::{ApiError, ApiQuery, Problem},
    middleware::org_scope::OrgScope,
    models::{enum_of, enum_str},
    state::AppState,
};

#[derive(Serialize, ToSchema)]
pub struct ResourceSummary {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub kind: String,
    pub identity: String,
    pub name: Option<String>,
    pub region: Option<String>,
    #[schema(value_type = Object)]
    pub tags: Value,
    pub first_seen_at: DateTime<FixedOffset>,
    pub last_seen_at: DateTime<FixedOffset>,
    /// Set when the resource was missing from a complete inventory.
    pub gone_at: Option<DateTime<FixedOffset>>,
}

fn summary(r: ResourceRow) -> ResourceSummary {
    ResourceSummary {
        id: r.id,
        connection_id: r.connection_id,
        kind: enum_str(r.kind),
        identity: r.identity,
        name: r.name,
        region: r.region,
        tags: serde_json::json!(r.tags),
        first_seen_at: r.first_seen_at.fixed_offset(),
        last_seen_at: r.last_seen_at.fixed_offset(),
        gone_at: r.gone_at.map(|t| t.fixed_offset()),
    }
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ResourceFilter {
    pub connection: Option<Uuid>,
    pub kind: Option<String>,
    /// Case-insensitive substring of name or identity.
    pub q: Option<String>,
}

#[utoipa::path(get, path = "/orgs/{org}/resources", tag = "resources",
    params(super::OrgPath, ResourceFilter, PageParams),
    responses((status = 200, body = Page<ResourceSummary>), (status = 404, body = Problem), (status = 422, body = Problem)))]
async fn list(
    State(app): State<AppState>,
    scope: OrgScope,
    ApiQuery(f): ApiQuery<ResourceFilter>,
    ApiQuery(p): ApiQuery<PageParams>,
) -> Result<Json<Page<ResourceSummary>>, ApiError> {
    let page = page_request(&p)?;
    // An unknown kind matches nothing, as when it was compared as stored text.
    let kind = match f.kind.as_deref().map(enum_of::<ResourceKind>) {
        Some(None) => {
            return Ok(Json(Page {
                items: vec![],
                next_cursor: None,
            }))
        }
        k => k.flatten(),
    };
    let filter = core::ResourceFilter {
        connection_id: f.connection,
        kind,
        q: f.q,
    };
    let got = app
        .actions
        .resources
        .list_resources
        .run(scope.organisation.id, filter, page)
        .await?;
    Ok(Json(Page::of(got).map(summary)))
}

pub fn api() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(list))
}
