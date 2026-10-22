use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, FixedOffset, Utc};
use loco_rs::{app::AppContext, bgworker::BackgroundWorker};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryTrait};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::{OrgIdPath, RunAccepted};
use crate::{
    api_error::{ApiError, ApiQuery, Problem},
    middleware::org_scope::OrgScope,
    models::{
        _entities::{connections, runs},
        find_in_org,
    },
    services::{
        manual_scan,
        pagination::{self, Page, PageParams},
    },
    workers::full_scan::{FullScanArgs, FullScanWorker},
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

fn summary(r: runs::Model) -> RunSummary {
    RunSummary {
        id: r.id,
        connection_id: r.connection_id,
        job_type: r.job_type,
        status: r.status,
        scheduled_at: r.scheduled_at,
        started_at: r.started_at,
        finished_at: r.finished_at,
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
    use runs::Column as C;
    let q = runs::Entity::find()
        .filter(C::OrganisationId.eq(scope.organisation_id))
        .apply_if(f.connection, |q, v| q.filter(C::ConnectionId.eq(v)))
        .apply_if(f.job_type, |q, v| q.filter(C::JobType.eq(v)));
    let page = pagination::fetch(
        &ctx.db,
        q,
        (C::ScheduledAt, C::Id),
        |m| (m.scheduled_at, m.id),
        &p,
    )
    .await?;
    Ok(Json(page.map(summary)))
}

#[utoipa::path(get, path = "/orgs/{org}/runs/{id}", tag = "runs", params(OrgIdPath),
    responses((status = 200, body = Run), (status = 404, body = Problem)))]
async fn show(
    State(ctx): State<AppContext>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
) -> Result<Json<Run>, ApiError> {
    let org = runs::Column::OrganisationId;
    let r = find_in_org::<runs::Entity>(&ctx.db, org, scope.organisation_id, &id).await?;
    Ok(Json(Run {
        attempts: r.attempts,
        stats: r.checkpoint.get("stats").cloned(),
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
    let org = connections::Column::OrganisationId;
    let c = find_in_org::<connections::Entity>(&ctx.db, org, scope.organisation_id, &id).await?;
    let out = manual_scan::request(&ctx.db, &c, scope.user_id, Utc::now()).await?;
    if out.created {
        FullScanWorker::perform_later(&ctx, FullScanArgs { run_id: out.run.id }).await?;
    }
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
