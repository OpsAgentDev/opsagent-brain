use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, FixedOffset};
use loco_rs::app::AppContext;
use opsagent_core::run;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::{OrgIdPath, RunAccepted};
use crate::{
    api_error::{ApiError, ApiQuery, Problem},
    app::actions,
    middleware::org_scope::OrgScope,
    models::enum_str,
    services::pagination::{self, Page, PageParams},
};

#[derive(Serialize, ToSchema)]
pub struct RunSummary {
    pub id: Uuid,
    pub connection_id: Option<Uuid>,
    /// `full_scan`, `verify`, ...
    pub job_type: String,
    /// `queued`, `running`, `done`, `partial`, `failed` or `skipped`.
    pub status: String,
    pub scheduled_at: DateTime<FixedOffset>,
    pub started_at: Option<DateTime<FixedOffset>>,
    pub finished_at: Option<DateTime<FixedOffset>>,
    pub partial_reason: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct Run {
    #[serde(flatten)]
    pub run: RunSummary,
    pub attempts: i32,
    /// Job statistics from the checkpoint (for `full_scan`: score, counts, partial); null if none.
    #[schema(value_type = Option<Object>)]
    pub stats: Option<Value>,
}

fn summary(r: run::Run) -> RunSummary {
    RunSummary {
        id: r.id,
        connection_id: r.connection_id,
        job_type: r.job_type,
        status: enum_str(r.status),
        scheduled_at: r.scheduled_at.fixed_offset(),
        started_at: r.started_at.map(|t| t.fixed_offset()),
        finished_at: r.finished_at.map(|t| t.fixed_offset()),
        partial_reason: r.partial_reason,
    }
}

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
    State(ctx): State<AppContext>,
    scope: OrgScope,
    ApiQuery(f): ApiQuery<RunFilter>,
    ApiQuery(p): ApiQuery<PageParams>,
) -> Result<Json<Page<RunSummary>>, ApiError> {
    let filter = run::RunFilter {
        connection_id: f.connection,
        job_type: f.job_type,
    };
    let list = &actions(&ctx)?.runs.list_runs;
    let got = list
        .run(scope.organisation_id, filter, pagination::request(&p)?)
        .await?;
    Ok(Json(Page::of(got).map(summary)))
}

#[utoipa::path(get, path = "/orgs/{org}/runs/{id}", tag = "runs", params(OrgIdPath),
    responses((status = 200, body = Run), (status = 404, body = Problem)))]
async fn show(
    State(ctx): State<AppContext>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
) -> Result<Json<Run>, ApiError> {
    let id = super::connections::parse_id(&id)?;
    let r = actions(&ctx)?
        .runs
        .get_run
        .run(scope.organisation_id, id)
        .await?;
    Ok(Json(Run {
        attempts: r.attempts,
        stats: Some(r.stats.clone()),
        run: summary(r),
    }))
}

#[utoipa::path(post, path = "/orgs/{org}/connections/{id}/scan", tag = "runs", params(OrgIdPath),
    responses((status = 202, body = RunAccepted), (status = 404, body = Problem),
        (status = 409, body = Problem, description = "Not connected or degraded (`connection_not_scannable`)."),
        (status = 429, body = Problem, description = "A scan ran within the last hour; see `Retry-After`.",
            headers(("Retry-After" = u64, description = "Seconds until a scan is allowed")))))]
async fn scan(
    State(ctx): State<AppContext>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
) -> Result<(StatusCode, Json<RunAccepted>), ApiError> {
    let id = super::connections::parse_id(&id)?;
    let scan = &actions(&ctx)?.runs.request_manual_scan;
    let out = scan.run(scope.organisation_id, scope.user_id, id).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(RunAccepted { run_id: out.run.id }),
    ))
}

pub fn api() -> OpenApiRouter<AppContext> {
    OpenApiRouter::new()
        .routes(routes!(list))
        .routes(routes!(show))
        .routes(routes!(scan))
}
