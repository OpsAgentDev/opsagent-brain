use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::NaiveTime;
use loco_rs::app::AppContext;
use opsagent_connectors::aws::client::short_id;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::{OrgIdPath, OrgPath, RunAccepted};
use crate::{
    api_error::{ApiError, ApiJson, Problem},
    app::{kek, registry},
    middleware::org_scope::OrgScope,
    models::{
        _entities::{connection_verifications, connections},
        connections::TEMPLATE_VERSION,
        find_in_org,
        organisations::valid_name,
    },
    services::connections as service,
    views::connections::{view, Connection},
};

fn stack_name(organisation_id: Uuid) -> String {
    format!("OpsAgent-Read-{}", short_id(&organisation_id))
}

async fn find(
    ctx: &AppContext,
    scope: &OrgScope,
    id: &str,
) -> Result<connections::Model, ApiError> {
    find_in_org::<connections::Entity>(
        &ctx.db,
        connections::Column::OrganisationId,
        scope.organisation_id,
        id,
    )
    .await
}

fn quick_create_url(organisation_id: Uuid, external_id: &str) -> Result<String, ApiError> {
    let principal = std::env::var("OPSAGENT_AWS_OUTBOUND_ROLE_ARN")
        .map_err(|_| ApiError::internal("OPSAGENT_AWS_OUTBOUND_ROLE_ARN is not set"))?;
    let base = std::env::var("OPSAGENT_TEMPLATE_BASE_URL")
        .unwrap_or_else(|_| "https://templates.opsagent.dev".into());
    let template = format!(
        "{}/aws/opsagent-read-role-v{TEMPLATE_VERSION}.yaml",
        base.trim_end_matches('/')
    );
    let e = |s: &str| urlencoding::encode(s).into_owned();
    Ok(format!(
        "https://console.aws.amazon.com/cloudformation/home#/stacks/quickcreate?templateURL={}&stackName={}\
         &param_ExternalId={}&param_OpsAgentPrincipal={}&param_OrgShortId={}&param_TemplateVersion={TEMPLATE_VERSION}",
        e(&template),
        stack_name(organisation_id),
        e(external_id),
        e(&principal),
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
    let name = valid_name(&body.display_name)?;
    let org_id = scope.organisation_id;
    let created = service::create(
        &ctx.db,
        kek(&ctx)?.as_ref(),
        &registry(&ctx)?,
        org_id,
        scope.user_id,
        &body.provider,
        name,
    )
    .await?;
    let url = created
        .spec
        .uses_template
        .then(|| quick_create_url(org_id, &created.creds.external_id))
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
    let rows = connections::Entity::find()
        .filter(connections::Column::OrganisationId.eq(scope.organisation_id))
        .order_by_asc(connections::Column::CreatedAt)
        .all(&ctx.db)
        .await?;
    Ok(Json(rows.iter().map(|c| view(c, None)).collect()))
}

#[utoipa::path(get, path = "/orgs/{org}/connections/{id}", tag = "connections", params(OrgIdPath),
    responses((status = 200, body = Connection), (status = 404, body = Problem)))]
async fn show(
    State(ctx): State<AppContext>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
) -> Result<Json<Connection>, ApiError> {
    let c = find(&ctx, &scope, &id).await?;
    let last = connection_verifications::Entity::find()
        .filter(connection_verifications::Column::ConnectionId.eq(c.id))
        .order_by_desc(connection_verifications::Column::CreatedAt)
        .one(&ctx.db)
        .await?;
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

/// `""` clears; otherwise a Slack conversation id.
fn valid_channel(s: &str) -> Result<Option<String>, ApiError> {
    if s.is_empty() {
        return Ok(None);
    }
    let ok = (9..=21).contains(&s.len())
        && matches!(s.as_bytes()[0], b'C' | b'G')
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
    ok.then(|| Some(s.to_owned()))
        .ok_or_else(|| ApiError::invalid("slack_channel_id must be a Slack channel id"))
}

fn valid_hhmm(field: &str, s: &str) -> Result<NaiveTime, ApiError> {
    (s.len() == 5)
        .then(|| NaiveTime::parse_from_str(s, "%H:%M").ok())
        .flatten()
        .ok_or_else(|| ApiError::invalid(format!("{field} must be HH:MM")))
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
    let c = find(&ctx, &scope, &id).await?;
    let hhmm =
        |field: &str, v: &Option<String>| v.as_deref().map(|t| valid_hhmm(field, t)).transpose();
    if body.api_rate_ceiling.is_some_and(|r| r < 1) {
        return Err(ApiError::invalid("api_rate_ceiling must be at least 1"));
    }
    let patch = service::Patch {
        display_name: body.display_name.as_deref().map(valid_name).transpose()?,
        scan_time_local: hhmm("scan_time_local", &body.scan_time_local)?,
        briefing_time_local: hhmm("briefing_time_local", &body.briefing_time_local)?,
        api_rate_ceiling: body.api_rate_ceiling,
        slack_channel_id: body
            .slack_channel_id
            .as_deref()
            .map(valid_channel)
            .transpose()?,
    };
    Ok(Json(view(&service::update(&ctx.db, c, patch).await?, None)))
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
    let c = find(&ctx, &scope, &id).await?;
    let run_id =
        service::request_verify(&ctx, kek(&ctx)?.as_ref(), &c, scope.user_id, &body.role_arn)
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
    let c = find(&ctx, &scope, &id).await?;
    let org_id = c.organisation_id;
    service::disconnect(&ctx.db, c, scope.user_id).await?;
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
