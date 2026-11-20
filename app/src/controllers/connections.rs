use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::{parse_id, OrgIdPath, OrgPath, RunAccepted};
use crate::{
    actions::connections::{stack_name, PatchInput, TEMPLATE_VERSION},
    api_error::{ApiError, ApiJson, Problem},
    middleware::org_scope::OrgScope,
    state::AppState,
    views::connections::{view, Connection},
};

#[derive(Deserialize, ToSchema)]
pub struct NewConnection {
    /// `aws`.
    pub provider: String,
    pub display_name: String,
}

#[derive(Serialize, ToSchema)]
pub struct CreatedConnection {
    pub id: Uuid,
    /// CloudFormation quick-create link for the read role; null for test providers.
    pub quick_create_url: Option<String>,
    pub template_version: String,
}

#[utoipa::path(post, path = "/orgs/{org}/connections", tag = "connections", params(OrgPath),
    request_body = NewConnection,
    responses((status = 201, body = CreatedConnection), (status = 403, body = Problem),
        (status = 404, body = Problem), (status = 422, body = Problem),
        (status = 503, body = Problem)))]
async fn create(
    State(app): State<AppState>,
    scope: OrgScope,
    ApiJson(body): ApiJson<NewConnection>,
) -> Result<(StatusCode, Json<CreatedConnection>), ApiError> {
    let c = &app.actions.connections;
    let created = c
        .create_connection
        .run(&scope, &body.provider, &body.display_name)
        .await?;
    let url = c.quick_create.link(scope.organisation.id, &created)?;
    Ok((
        StatusCode::CREATED,
        Json(CreatedConnection {
            id: created.id,
            quick_create_url: url,
            template_version: TEMPLATE_VERSION.into(),
        }),
    ))
}

#[utoipa::path(get, path = "/orgs/{org}/connections", tag = "connections", params(OrgPath),
    responses((status = 200, body = Vec<Connection>), (status = 404, body = Problem)))]
async fn list(
    State(app): State<AppState>,
    scope: OrgScope,
) -> Result<Json<Vec<Connection>>, ApiError> {
    let list = &app.actions.connections.list_connections;
    let rows = list.run(scope.organisation.id).await?;
    Ok(Json(rows.iter().map(|c| view(c, None)).collect()))
}

#[utoipa::path(get, path = "/orgs/{org}/connections/{id}", tag = "connections", params(OrgIdPath),
    responses((status = 200, body = Connection), (status = 404, body = Problem)))]
async fn show(
    State(app): State<AppState>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
) -> Result<Json<Connection>, ApiError> {
    let get = &app.actions.connections.get_connection;
    let (c, last) = get.run(scope.organisation.id, parse_id(&id)?).await?;
    Ok(Json(view(&c, last.as_ref())))
}

#[derive(Deserialize, ToSchema)]
pub struct ConnectionPatch {
    pub display_name: Option<String>,
    /// `HH:MM` in the organisation's timezone; the nightly scan moves there from the next day.
    pub scan_time_local: Option<String>,
    /// `HH:MM`.
    pub briefing_time_local: Option<String>,
    /// At least 1.
    pub api_rate_ceiling: Option<i32>,
    /// Slack channel id (`C…` or `G…`) for this connection's deliveries; `""` clears it.
    /// Email recipients are managed through `/orgs/{org}/recipients` with `connection_id`.
    pub slack_channel_id: Option<String>,
    /// Tell the owners right away about new critical findings (default on).
    pub urgent_alerts: Option<bool>,
}

#[utoipa::path(patch, path = "/orgs/{org}/connections/{id}", tag = "connections", params(OrgIdPath),
    request_body = ConnectionPatch,
    responses((status = 200, body = Connection), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 409, body = Problem), (status = 422, body = Problem)))]
async fn update(
    State(app): State<AppState>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
    ApiJson(body): ApiJson<ConnectionPatch>,
) -> Result<Json<Connection>, ApiError> {
    scope.require_owner()?;
    let id = parse_id(&id)?;
    let input = PatchInput {
        display_name: body.display_name,
        scan_time_local: body.scan_time_local,
        briefing_time_local: body.briefing_time_local,
        api_rate_ceiling: body.api_rate_ceiling,
        slack_channel_id: body.slack_channel_id,
        urgent_alerts: body.urgent_alerts,
    };
    let update = &app.actions.connections.update_connection;
    Ok(Json(view(
        &update.run(scope.organisation.id, id, input).await?,
        None,
    )))
}

#[derive(Deserialize, ToSchema)]
pub struct VerifyBody {
    /// The read role's ARN from the stack outputs (required for `aws`).
    #[serde(default)]
    pub role_arn: String,
}

#[utoipa::path(post, path = "/orgs/{org}/connections/{id}/verify", tag = "connections", params(OrgIdPath),
    request_body = VerifyBody,
    responses((status = 202, body = RunAccepted), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 409, body = Problem), (status = 422, body = Problem)))]
async fn verify(
    State(app): State<AppState>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
    ApiJson(body): ApiJson<VerifyBody>,
) -> Result<(StatusCode, Json<RunAccepted>), ApiError> {
    let verify = &app.actions.connections.request_verify;
    let run_id = verify.run(&scope, parse_id(&id)?, &body.role_arn).await?;
    Ok((StatusCode::ACCEPTED, Json(RunAccepted { run_id })))
}

#[derive(Serialize, ToSchema)]
pub struct ReconnectLink {
    /// CloudFormation quick-create link with this connection's ExternalId; null for test providers.
    pub quick_create_url: Option<String>,
    /// The stack to delete first if it still exists: a second one of this name cannot be created.
    pub stack_name: String,
}

/// Owner only, for a `revoked` connection or one still `pending` (409 `connection_not_revoked`
/// otherwise). The owner launches the stack (again) and calls `verify`; the connection and its
/// findings are kept.
#[utoipa::path(post, path = "/orgs/{org}/connections/{id}/reconnect", tag = "connections", params(OrgIdPath),
    responses((status = 200, body = ReconnectLink), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 409, body = Problem)))]
async fn reconnect(
    State(app): State<AppState>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
) -> Result<Json<ReconnectLink>, ApiError> {
    scope.require_owner()?;
    let org_id = scope.organisation.id;
    let link = &app.actions.connections.reconnect_link;
    let got = link
        .run(org_id, scope.member.user_id, parse_id(&id)?)
        .await?;
    let url = app.actions.connections.quick_create.link(org_id, &got)?;
    Ok(Json(ReconnectLink {
        quick_create_url: url,
        stack_name: stack_name(org_id),
    }))
}

#[derive(Serialize, ToSchema)]
pub struct Disconnected {
    /// Always `disconnected`.
    pub status: String,
    pub next_step: String,
}

#[utoipa::path(delete, path = "/orgs/{org}/connections/{id}", tag = "connections", params(OrgIdPath),
    responses((status = 200, body = Disconnected), (status = 403, body = Problem), (status = 404, body = Problem)))]
async fn disconnect(
    State(app): State<AppState>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
) -> Result<Json<Disconnected>, ApiError> {
    scope.require_owner()?;
    let org_id = scope.organisation.id;
    let disconnect = &app.actions.connections.disconnect_connection;
    disconnect
        .run(org_id, scope.member.user_id, parse_id(&id)?)
        .await?;
    Ok(Json(Disconnected {
        status: "disconnected".into(),
        next_step: format!(
            "Delete the CloudFormation stack {} in your account to revoke access.",
            stack_name(org_id)
        ),
    }))
}

pub fn api() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(create, list))
        .routes(routes!(show, update, disconnect))
        .routes(routes!(verify))
        .routes(routes!(reconnect))
}
