use axum::{extract::State, Json};
use opsagent_core::resource::{self as core, ResourceKind};
use serde::Deserialize;
use utoipa::IntoParams;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use crate::{
    api_error::{ApiError, ApiQuery, Problem},
    middleware::org_scope::OrgScope,
    models::enum_of,
    state::AppState,
    views::{
        page::{page_request, Page, PageParams},
        resources::{summary, ResourceSummary},
    },
};

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
