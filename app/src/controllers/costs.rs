use axum::{
    extract::{Path, State},
    Json,
};
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{parse_id, OrgIdPath};
use crate::{
    api_error::{ApiError, Problem},
    middleware::org_scope::OrgScope,
    state::AppState,
    views::costs::{series, CostSeries},
};

/// Stored daily spend per service for the newest 60 days, and the days check 01 flagged.
#[utoipa::path(get, path = "/orgs/{org}/connections/{id}/costs", tag = "costs", params(OrgIdPath),
    responses((status = 200, body = CostSeries), (status = 404, body = Problem)))]
async fn show(
    State(app): State<AppState>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
) -> Result<Json<CostSeries>, ApiError> {
    let get = &app.actions.resources.get_costs;
    let costs = get.run(scope.organisation.id, parse_id(&id)?).await?;
    Ok(Json(series(costs)))
}

pub fn api() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(show))
}
