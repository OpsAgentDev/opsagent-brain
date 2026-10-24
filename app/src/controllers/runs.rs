use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use opsagent_core::run;
use serde::Deserialize;
use utoipa::IntoParams;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::{OrgIdPath, RunAccepted};
use crate::{
    api_error::{ApiError, ApiQuery, Problem},
    middleware::org_scope::OrgScope,
    state::AppState,
    views::{
        page::{page_request, Page, PageParams},
        runs::{run_view, summary, Run, RunSummary},
    },
};

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct RunFilter {
    pub connection: Option<Uuid>,
    /// Job type.
    #[serde(rename = "type")]
    #[param(rename = "type")]
    pub job_type: Option<String>,
}

#[utoipa::path(get, path = "/orgs/{org}/runs", tag = "runs",
    params(super::OrgPath, RunFilter, PageParams),
    responses((status = 200, body = Page<RunSummary>), (status = 404, body = Problem), (status = 422, body = Problem)))]
async fn list(
    State(app): State<AppState>,
    scope: OrgScope,
    ApiQuery(f): ApiQuery<RunFilter>,
    ApiQuery(p): ApiQuery<PageParams>,
) -> Result<Json<Page<RunSummary>>, ApiError> {
    let filter = run::RunFilter {
        connection_id: f.connection,
        job_type: f.job_type,
    };
    let list = &app.actions.runs.list_runs;
    let got = list
        .run(scope.organisation.id, filter, page_request(&p)?)
        .await?;
    Ok(Json(Page::of(got).map(summary)))
}

#[utoipa::path(get, path = "/orgs/{org}/runs/{id}", tag = "runs", params(OrgIdPath),
    responses((status = 200, body = Run), (status = 404, body = Problem)))]
async fn show(
    State(app): State<AppState>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
) -> Result<Json<Run>, ApiError> {
    let id = super::parse_id(&id)?;
    let r = app
        .actions
        .runs
        .get_run
        .run(scope.organisation.id, id)
        .await?;
    Ok(Json(run_view(r)))
}

#[utoipa::path(post, path = "/orgs/{org}/connections/{id}/scan", tag = "runs", params(OrgIdPath),
    responses((status = 202, body = RunAccepted), (status = 404, body = Problem),
        (status = 409, body = Problem, description = "Not connected or degraded (`connection_not_scannable`)."),
        (status = 429, body = Problem, description = "A scan ran within the last hour; see `Retry-After`.",
            headers(("Retry-After" = u64, description = "Seconds until a scan is allowed")))))]
async fn scan(
    State(app): State<AppState>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
) -> Result<(StatusCode, Json<RunAccepted>), ApiError> {
    let id = super::parse_id(&id)?;
    let scan = &app.actions.runs.request_manual_scan;
    let out = scan
        .run(scope.organisation.id, scope.member.user_id, id)
        .await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(RunAccepted { run_id: out.run.id }),
    ))
}

pub fn api() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list))
        .routes(routes!(show))
        .routes(routes!(scan))
}
