use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use loco_rs::app::AppContext;
use opsagent_connectors::aws::client::short_id;
use opsagent_core::org::valid_name;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::{OrgIdPath, OrgPath, RunAccepted};
use crate::{
    actions::connections::{PatchInput, TEMPLATE_VERSION},
    api_error::{ApiError, ApiJson, Problem},
    app::{actions, state},
    config::Config,
    middleware::org_scope::OrgScope,
    views::connections::{view, Connection},
};

fn stack_name(organisation_id: Uuid) -> String {
    format!("OpsAgent-Read-{}", short_id(&organisation_id))
}

/// A malformed id is the same 404 as an unknown id or another org's.
pub(super) fn parse_id(id: &str) -> Result<Uuid, ApiError> {
    id.parse().map_err(|_| ApiError::not_found())
}

fn quick_create_url(
    c: &Config,
    organisation_id: Uuid,
    external_id: &str,
) -> Result<String, ApiError> {
    let principal = c
        .aws_outbound_role_arn
        .as_deref()
        .ok_or_else(|| ApiError::internal("OPSAGENT_AWS_OUTBOUND_ROLE_ARN is not set"))?;
    let template = format!(
        "{}/aws/opsagent-read-role-v{TEMPLATE_VERSION}.yaml",
        c.template_base_url.trim_end_matches('/')
    );
    let e = |s: &str| urlencoding::encode(s).into_owned();
    Ok(format!(
        "https://console.aws.amazon.com/cloudformation/home#/stacks/quickcreate?templateURL={}&stackName={}\
         &param_ExternalId={}&param_OpsAgentPrincipal={}&param_OrgShortId={}&param_TemplateVersion={TEMPLATE_VERSION}",
        e(&template),
        stack_name(organisation_id),
        e(external_id),
        e(principal),
        short_id(&organisation_id),
    ))
}

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
        (status = 404, body = Problem), (status = 422, body = Problem)))]
async fn create(
    State(ctx): State<AppContext>,
    scope: OrgScope,
    ApiJson(body): ApiJson<NewConnection>,
) -> Result<(StatusCode, Json<CreatedConnection>), ApiError> {
    scope.require_owner()?;
    let name = valid_name(&body.display_name).map_err(ApiError::invalid)?;
    let org_id = scope.organisation.id;
    let create = &actions(&ctx)?.connections.create_connection;
    let created = create
        .run(org_id, scope.member.user_id, &body.provider, name)
        .await?;
    let app = state(&ctx)?;
    let url = created
        .spec
        .uses_template
        .then(|| quick_create_url(&app.config, org_id, &created.creds.external_id))
        .transpose()?;
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
    State(ctx): State<AppContext>,
    scope: OrgScope,
) -> Result<Json<Vec<Connection>>, ApiError> {
    let list = &actions(&ctx)?.connections.list_connections;
    let rows = list.run(scope.organisation.id).await?;
    Ok(Json(rows.iter().map(|c| view(c, None)).collect()))
}

#[utoipa::path(get, path = "/orgs/{org}/connections/{id}", tag = "connections", params(OrgIdPath),
    responses((status = 200, body = Connection), (status = 404, body = Problem)))]
async fn show(
    State(ctx): State<AppContext>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
) -> Result<Json<Connection>, ApiError> {
    let get = &actions(&ctx)?.connections.get_connection;
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
}

#[utoipa::path(patch, path = "/orgs/{org}/connections/{id}", tag = "connections", params(OrgIdPath),
    request_body = ConnectionPatch,
    responses((status = 200, body = Connection), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 409, body = Problem), (status = 422, body = Problem)))]
async fn update(
    State(ctx): State<AppContext>,
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
    };
    let update = &actions(&ctx)?.connections.update_connection;
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
    State(ctx): State<AppContext>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
    ApiJson(body): ApiJson<VerifyBody>,
) -> Result<(StatusCode, Json<RunAccepted>), ApiError> {
    scope.require_owner()?;
    let verify = &actions(&ctx)?.connections.request_verify;
    let (org_id, id) = (scope.organisation.id, parse_id(&id)?);
    let run_id = verify
        .run(org_id, scope.member.user_id, id, &body.role_arn)
        .await?;
    Ok((StatusCode::ACCEPTED, Json(RunAccepted { run_id })))
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
    State(ctx): State<AppContext>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
) -> Result<Json<Disconnected>, ApiError> {
    scope.require_owner()?;
    let org_id = scope.organisation.id;
    let disconnect = &actions(&ctx)?.connections.disconnect_connection;
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

pub fn api() -> OpenApiRouter<AppContext> {
    OpenApiRouter::new()
        .routes(routes!(create, list))
        .routes(routes!(show, update, disconnect))
        .routes(routes!(verify))
}
