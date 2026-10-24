//! Connected agents: the OAuth grants an organisation's members have given AI clients.
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, FixedOffset};
use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::{parse_id, OrgIdPath, OrgPath};
use crate::{
    api_error::{ApiError, Problem},
    middleware::org_scope::OrgScope,
    state::AppState,
};

#[derive(Serialize, ToSchema)]
pub struct AgentView {
    pub grant_id: Uuid,
    pub client_name: String,
    /// `dynamic` or `metadata_document`.
    pub client_kind: String,
    pub member_email: String,
    pub created_at: DateTime<FixedOffset>,
    pub last_used_at: Option<DateTime<FixedOffset>>,
}

#[utoipa::path(get, path = "/orgs/{org}/agents", tag = "agents", params(OrgPath),
    responses((status = 200, body = Vec<AgentView>), (status = 404, body = Problem)))]
async fn list(
    State(app): State<AppState>,
    scope: OrgScope,
) -> Result<Json<Vec<AgentView>>, ApiError> {
    let rows = app.actions.oauth.list_agents.run(&scope).await?;
    Ok(Json(
        rows.into_iter()
            .map(|a| AgentView {
                grant_id: a.grant_id,
                client_name: a.client_name,
                client_kind: a.client_kind.into(),
                member_email: a.member_email,
                created_at: a.created_at.fixed_offset(),
                last_used_at: a.last_used_at.map(|t| t.fixed_offset()),
            })
            .collect(),
    ))
}

#[utoipa::path(delete, path = "/orgs/{org}/agents/{id}", tag = "agents", params(OrgIdPath),
    responses((status = 204), (status = 404, body = Problem)))]
async fn revoke(
    State(app): State<AppState>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let revoke = &app.actions.oauth.revoke_agent;
    revoke.run(&scope, parse_id(&id)?, app.clock.now()).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn api() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list))
        .routes(routes!(revoke))
}
