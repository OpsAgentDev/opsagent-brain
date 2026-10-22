use axum::{
    extract::{Path, State},
    Json,
};
use chrono::{DateTime, FixedOffset, Utc};
use loco_rs::app::AppContext;
use sea_orm::{
    prelude::Decimal, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect, QueryTrait,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::OrgIdPath;
use crate::{
    api_error::{ApiError, ApiQuery, Problem},
    middleware::org_scope::OrgScope,
    models::{
        _entities::{evidence, finding_events, findings},
        find_in_org,
    },
    services::pagination::{self, Page, PageParams},
};

const EVENTS_SHOWN: u64 = 20;

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

fn summary(f: findings::Model) -> FindingSummary {
    FindingSummary {
        id: f.id,
        connection_id: f.connection_id,
        check_id: f.check_id,
        resource_identity: f.resource_identity,
        variant: f.variant,
        severity: f.severity,
        status: f.status,
        title: f.title,
        cost_monthly_usd: f.cost_monthly_usd,
        created_at: f.created_at,
        updated_at: f.updated_at,
    }
}

fn full(f: findings::Model) -> Finding {
    Finding {
        summary: f.summary.clone(),
        next_step: f.next_step.clone(),
        accepted_reason: f.accepted_reason.clone(),
        accepted_until: f.accepted_until,
        snoozed_until: f.snoozed_until,
        resolved_at: f.resolved_at,
        resolved_reason: f.resolved_reason.clone(),
        first_seen_run_id: f.first_seen_run_id,
        last_seen_run_id: f.last_seen_run_id,
        finding: summary(f),
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
    State(ctx): State<AppContext>,
    scope: OrgScope,
    ApiQuery(f): ApiQuery<FindingFilter>,
    ApiQuery(p): ApiQuery<PageParams>,
) -> Result<Json<Page<FindingSummary>>, ApiError> {
    use findings::Column as C;
    let q = findings::Entity::find()
        .filter(C::OrganisationId.eq(scope.organisation_id))
        .apply_if(f.connection, |q, v| q.filter(C::ConnectionId.eq(v)))
        .apply_if(f.status, |q, v| q.filter(C::Status.eq(v)))
        .apply_if(f.severity, |q, v| q.filter(C::Severity.eq(v)))
        .apply_if(f.check, |q, v| q.filter(C::CheckId.eq(v)));
    let page = pagination::fetch(
        &ctx.db,
        q,
        (C::CreatedAt, C::Id),
        |m| (m.created_at, m.id),
        &p,
    )
    .await?;
    Ok(Json(page.map(summary)))
}

/// Org-filtered: another org's finding is the same 404 as an unknown id.
async fn find(ctx: &AppContext, scope: &OrgScope, id: &str) -> Result<findings::Model, ApiError> {
    let org = findings::Column::OrganisationId;
    find_in_org::<findings::Entity>(&ctx.db, org, scope.organisation_id, id).await
}

#[utoipa::path(get, path = "/orgs/{org}/findings/{id}", tag = "findings", params(OrgIdPath),
    responses((status = 200, body = FindingDetail), (status = 404, body = Problem)))]
async fn show(
    State(ctx): State<AppContext>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
) -> Result<Json<FindingDetail>, ApiError> {
    let f = find(&ctx, &scope, &id).await?;
    let evidence = evidence::Entity::find()
        .filter(evidence::Column::FindingId.eq(f.id))
        .filter(evidence::Column::ExpiresAt.gt(Utc::now()))
        .order_by_desc(evidence::Column::CreatedAt)
        .all(&ctx.db)
        .await?
        .into_iter()
        .map(|e| EvidenceItem {
            source: e.source,
            excerpt: e.excerpt,
            redacted: e.redacted,
            run_id: e.run_id,
            created_at: e.created_at,
        })
        .collect();
    let events = finding_events::Entity::find()
        .filter(finding_events::Column::FindingId.eq(f.id))
        .order_by_desc(finding_events::Column::CreatedAt)
        .order_by_desc(finding_events::Column::Id)
        .limit(EVENTS_SHOWN)
        .all(&ctx.db)
        .await?
        .into_iter()
        .map(|e| FindingEvent {
            event_type: e.event_type,
            from_severity: e.from_severity,
            to_severity: e.to_severity,
            run_id: Some(e.run_id),
            created_at: e.created_at,
        })
        .collect();
    Ok(Json(FindingDetail {
        finding: full(f),
        evidence,
        events,
        explanation: None,
    }))
}

pub fn api() -> OpenApiRouter<AppContext> {
    OpenApiRouter::new()
        .routes(routes!(list))
        .routes(routes!(show))
}
