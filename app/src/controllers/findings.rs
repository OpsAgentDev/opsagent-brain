use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use opsagent_core::finding::{self as core, Severity};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::OrgIdPath;
use crate::{
    actions::findings::FindingAction,
    api_error::{ApiError, ApiJson, ApiQuery, Problem},
    middleware::org_scope::OrgScope,
    models::enum_of,
    state::AppState,
    views::{
        findings::{detail, full, summary, Finding, FindingDetail, FindingSummary},
        page::{page_request, Page, PageParams},
    },
};

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct FindingFilter {
    pub connection: Option<Uuid>,
    pub status: Option<String>,
    pub severity: Option<String>,
    /// Check id, e.g. `no_mfa`.
    pub check: Option<String>,
}

#[utoipa::path(get, path = "/orgs/{org}/findings", tag = "findings",
    params(super::OrgPath, FindingFilter, PageParams),
    responses((status = 200, body = Page<FindingSummary>), (status = 404, body = Problem), (status = 422, body = Problem)))]
async fn list(
    State(app): State<AppState>,
    scope: OrgScope,
    ApiQuery(f): ApiQuery<FindingFilter>,
    ApiQuery(p): ApiQuery<PageParams>,
) -> Result<Json<Page<FindingSummary>>, ApiError> {
    let page = page_request(&p)?;
    // An unknown severity matches nothing, as when it was compared as stored text.
    let severity = match f.severity.as_deref().map(enum_of::<Severity>) {
        Some(None) => {
            return Ok(Json(Page {
                items: vec![],
                next_cursor: None,
            }))
        }
        s => s.flatten(),
    };
    let filter = core::FindingFilter {
        connection_id: f.connection,
        status: f.status,
        severity,
        check_id: f.check,
        ..Default::default()
    };
    let got = app
        .actions
        .findings
        .list_findings
        .run(scope.organisation.id, filter, page)
        .await?;
    Ok(Json(Page::of(got).map(summary)))
}

#[utoipa::path(get, path = "/orgs/{org}/findings/{id}", tag = "findings", params(OrgIdPath),
    responses((status = 200, body = FindingDetail), (status = 404, body = Problem)))]
async fn show(
    State(app): State<AppState>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
) -> Result<Json<FindingDetail>, ApiError> {
    let d = app
        .actions
        .findings
        .get_finding
        .run(scope.organisation.id, super::parse_id(&id)?)
        .await?;
    Ok(Json(detail(d)))
}

async fn act(
    app: &AppState,
    scope: &OrgScope,
    id: &str,
    action: FindingAction,
) -> Result<Json<Finding>, ApiError> {
    let id = super::parse_id(id)?;
    let updated = app
        .actions
        .findings
        .change_finding_status
        .run(scope.organisation.id, scope.member.user_id, id, action)
        .await?;
    Ok(Json(full(updated)))
}

#[derive(Deserialize, ToSchema)]
pub struct AcceptBody {
    /// Required.
    pub reason: Option<String>,
    /// Default now + 90 days; at most 365 days ahead.
    pub until: Option<DateTime<Utc>>,
}

#[utoipa::path(post, path = "/orgs/{org}/findings/{id}/accept", tag = "findings", params(OrgIdPath),
    request_body = AcceptBody,
    responses((status = 200, body = Finding), (status = 404, body = Problem), (status = 422, body = Problem)))]
async fn accept(
    State(app): State<AppState>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
    ApiJson(b): ApiJson<AcceptBody>,
) -> Result<Json<Finding>, ApiError> {
    let action = FindingAction::Accept {
        reason: b.reason,
        until: b.until,
    };
    act(&app, &scope, &id, action).await
}

#[derive(Deserialize, ToSchema)]
pub struct SnoozeBody {
    /// At most 30 days ahead.
    pub until: DateTime<Utc>,
}

#[utoipa::path(post, path = "/orgs/{org}/findings/{id}/snooze", tag = "findings", params(OrgIdPath),
    request_body = SnoozeBody,
    responses((status = 200, body = Finding), (status = 404, body = Problem), (status = 422, body = Problem)))]
async fn snooze(
    State(app): State<AppState>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
    ApiJson(b): ApiJson<SnoozeBody>,
) -> Result<Json<Finding>, ApiError> {
    act(&app, &scope, &id, FindingAction::Snooze { until: b.until }).await
}

#[utoipa::path(post, path = "/orgs/{org}/findings/{id}/reopen", tag = "findings", params(OrgIdPath),
    responses((status = 200, body = Finding), (status = 404, body = Problem), (status = 422, body = Problem)))]
async fn reopen(
    State(app): State<AppState>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
) -> Result<Json<Finding>, ApiError> {
    act(&app, &scope, &id, FindingAction::Reopen).await
}

#[derive(Deserialize, ToSchema)]
pub struct ExplanationReport {
    /// What is wrong with the explanation; at most 2000 characters.
    pub note: String,
}

#[utoipa::path(post, path = "/orgs/{org}/findings/{id}/report-explanation", tag = "findings",
    params(OrgIdPath), request_body = ExplanationReport,
    responses((status = 204), (status = 404, body = Problem), (status = 422, body = Problem)))]
async fn report_explanation(
    State(app): State<AppState>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
    ApiJson(b): ApiJson<ExplanationReport>,
) -> Result<StatusCode, ApiError> {
    app.actions
        .findings
        .report_explanation
        .run(
            scope.organisation.id,
            scope.member.user_id,
            super::parse_id(&id)?,
            &b.note,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn api() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list))
        .routes(routes!(show))
        .routes(routes!(accept))
        .routes(routes!(snooze))
        .routes(routes!(reopen))
        .routes(routes!(report_explanation))
}
