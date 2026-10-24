use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, FixedOffset, Utc};
use opsagent_core::finding::{self as core, Severity, StoredEvidence};
use sea_orm::prelude::Decimal;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::{
    page::{page_request, Page, PageParams},
    OrgIdPath,
};
use crate::{
    actions::findings::FindingAction,
    api_error::{ApiError, ApiJson, ApiQuery, Problem},
    middleware::org_scope::OrgScope,
    models::{enum_of, enum_str},
    state::AppState,
};

#[derive(Serialize, ToSchema)]
pub struct FindingSummary {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub check_id: String,
    pub resource_identity: String,
    pub variant: String,
    /// `critical`, `high`, `medium`, `low` or `info`.
    pub severity: String,
    /// `open`, `resolved`, `accepted`, `snoozed` or `flapping`.
    pub status: String,
    pub title: String,
    pub cost_monthly_usd: Option<Decimal>,
    pub created_at: DateTime<FixedOffset>,
    pub updated_at: DateTime<FixedOffset>,
}

#[derive(Serialize, ToSchema)]
pub struct Finding {
    #[serde(flatten)]
    pub finding: FindingSummary,
    pub summary: Option<String>,
    pub next_step: Option<String>,
    pub accepted_reason: Option<String>,
    pub accepted_until: Option<DateTime<FixedOffset>>,
    pub snoozed_until: Option<DateTime<FixedOffset>>,
    pub resolved_at: Option<DateTime<FixedOffset>>,
    pub resolved_reason: Option<String>,
    pub first_seen_run_id: Option<Uuid>,
    pub last_seen_run_id: Option<Uuid>,
}

#[derive(Serialize, ToSchema)]
pub struct EvidenceItem {
    pub source: String,
    /// Redacted before storage.
    pub excerpt: String,
    pub redacted: bool,
    pub run_id: Uuid,
    pub created_at: DateTime<FixedOffset>,
}

#[derive(Serialize, ToSchema)]
pub struct FindingEvent {
    pub event_type: String,
    pub from_severity: Option<String>,
    pub to_severity: Option<String>,
    /// Null for customer actions.
    pub run_id: Option<Uuid>,
    pub created_at: DateTime<FixedOffset>,
}

#[derive(Serialize, ToSchema)]
pub struct FindingDetail {
    #[serde(flatten)]
    pub finding: Finding,
    pub evidence: Vec<EvidenceItem>,
    /// Newest first, at most 20.
    pub events: Vec<FindingEvent>,
    /// Model explanation; null until explanations exist.
    #[schema(value_type = Option<Object>)]
    pub explanation: Option<Value>,
}

pub(crate) fn summary(f: core::Finding) -> FindingSummary {
    FindingSummary {
        id: f.id,
        connection_id: f.connection_id,
        check_id: f.key.check_id,
        resource_identity: f.key.resource_identity,
        variant: f.key.variant,
        severity: enum_str(f.severity),
        status: f.status,
        title: f.title,
        cost_monthly_usd: f.cost_monthly_usd,
        created_at: f.created_at.fixed_offset(),
        updated_at: f.updated_at.fixed_offset(),
    }
}

pub(crate) fn full(f: core::Finding) -> Finding {
    Finding {
        summary: f.summary.clone(),
        next_step: f.next_step.clone(),
        accepted_reason: f.accepted_reason.clone(),
        accepted_until: f.accepted_until.map(|t| t.fixed_offset()),
        snoozed_until: f.snoozed_until.map(|t| t.fixed_offset()),
        resolved_at: f.resolved_at.map(|t| t.fixed_offset()),
        resolved_reason: f.resolved_reason.clone(),
        first_seen_run_id: f.first_seen_run_id,
        last_seen_run_id: f.last_seen_run_id,
        finding: summary(f),
    }
}

fn evidence_item(e: StoredEvidence) -> EvidenceItem {
    EvidenceItem {
        source: e.source,
        excerpt: e.excerpt,
        redacted: e.redacted,
        run_id: e.run_id,
        created_at: e.created_at.fixed_offset(),
    }
}

fn event(e: core::FindingEvent) -> FindingEvent {
    FindingEvent {
        event_type: e.kind,
        from_severity: e.from_severity.map(enum_str),
        to_severity: e.to_severity.map(enum_str),
        run_id: e.run_id,
        created_at: e.at.fixed_offset(),
    }
}

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

/// The wire view of one finding with its evidence and events (REST and MCP).
pub(crate) fn detail(d: crate::actions::findings::FindingDetail) -> FindingDetail {
    FindingDetail {
        finding: full(d.finding),
        evidence: d.evidence.into_iter().map(evidence_item).collect(),
        events: d.events.into_iter().map(event).collect(),
        explanation: None,
    }
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
