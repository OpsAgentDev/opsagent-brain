use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, FixedOffset};
use loco_rs::app::AppContext;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tower_sessions::Session;
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::{OrgIdPath, OrgPath};
use crate::{
    adapters::slack::Channel,
    api_error::{ApiError, Problem},
    app::kek,
    middleware::{
        org_scope::{AuthUser, OrgScope},
        slack,
    },
    models::{_entities::members, magic_links::new_token, members::OWNER},
    services::integrations as service,
    settings::Settings,
};

/// Session key holding `(state, organisation_id)` for the one Slack install in flight.
const SLACK_KEY: &str = "slack_oauth";

#[derive(Serialize, ToSchema)]
pub struct SlackStart {
    pub authorize_url: String,
}

#[utoipa::path(post, path = "/orgs/{org}/integrations/slack/start", tag = "integrations", params(OrgPath),
    responses((status = 200, body = SlackStart), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 503, body = Problem)))]
async fn slack_start(
    State(ctx): State<AppContext>,
    scope: OrgScope,
    session: Session,
) -> Result<Json<SlackStart>, ApiError> {
    scope.require_owner()?;
    let state = new_token();
    let authorize_url = service::slack_authorize_url(&Settings::get(&ctx), &state)?;
    // Overwrites any earlier state, so only the latest start can complete.
    session
        .insert(SLACK_KEY, (state, scope.organisation_id))
        .await?;
    Ok(Json(SlackStart { authorize_url }))
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SlackCallback {
    pub code: Option<String>,
    pub state: Option<String>,
    /// Set by Slack when the user cancels (`access_denied`).
    pub error: Option<String>,
}

fn to_web(s: &Settings, query: &str) -> Response {
    let to = format!(
        "{}/settings/delivery?{query}",
        s.web_base_url.trim_end_matches('/')
    );
    (StatusCode::FOUND, [(header::LOCATION, to)]).into_response()
}

fn bad_state() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "oauth_state",
        "OAuth state mismatch; start the Slack install again.",
    )
}

/// The organisation the session's pending install was started for, if `state` matches it
/// and the user still owns that organisation. The stored state is consumed either way.
async fn claim_state(
    ctx: &AppContext,
    session: &Session,
    user_id: Uuid,
    state: Option<&str>,
) -> Result<Uuid, ApiError> {
    let stored = session.remove::<(String, Uuid)>(SLACK_KEY).await?;
    let matches = |s: &str| state.is_some_and(|q| bool::from(s.as_bytes().ct_eq(q.as_bytes())));
    let Some((_, org_id)) = stored.filter(|(s, _)| matches(s)) else {
        return Err(bad_state());
    };
    let owner = members::Entity::find()
        .filter(members::Column::OrganisationId.eq(org_id))
        .filter(members::Column::UserId.eq(user_id))
        .filter(members::Column::Role.eq(OWNER))
        .one(&ctx.db)
        .await?;
    owner.map(|_| org_id).ok_or_else(ApiError::forbidden)
}

#[utoipa::path(get, path = "/integrations/slack/callback", tag = "integrations", params(SlackCallback),
    responses((status = 302, description = "To `WEB_BASE_URL/settings/delivery?slack=connected`, or `?slack=error&code=<code>` (`signed_out` without a session)"),
        (status = 403, body = Problem)))]
async fn slack_callback(
    State(ctx): State<AppContext>,
    session: Session,
    user: Result<AuthUser, ApiError>,
    Query(q): Query<SlackCallback>,
) -> Result<Response, ApiError> {
    let s = Settings::get(&ctx);
    let Ok(AuthUser(user_id)) = user else {
        return Ok(to_web(&s, "slack=error&code=signed_out"));
    };
    let org_id = claim_state(&ctx, &session, user_id, q.state.as_deref()).await?;
    let fail = |code: &str| Ok(to_web(&s, &format!("slack=error&code={code}")));
    if q.error.is_some() {
        return fail("access_denied");
    }
    let Some(code) = q.code else {
        return fail("missing_code");
    };
    if s.slack_client_id.is_empty() || s.slack_client_secret.is_empty() {
        return fail("slack_not_configured");
    }
    let redirect = service::slack_redirect_uri(&s);
    let install = match slack(&ctx)
        .oauth_access(&s.slack_client_id, &s.slack_client_secret, &code, &redirect)
        .await
    {
        Ok(i) => i,
        Err(e) => {
            tracing::warn!(error_code = e.code(), "slack oauth exchange failed");
            return fail(&urlencoding::encode(e.code()));
        }
    };
    let kek = kek(&ctx)?;
    // Any other failure is internal and already logged by `ApiError::internal`.
    if let Err(e) = service::save_slack(&ctx.db, kek.as_ref(), org_id, user_id, &install).await {
        return fail(match e.code() {
            service::WORKSPACE_IN_USE => service::WORKSPACE_IN_USE,
            _ => "internal",
        });
    }
    Ok(to_web(&s, "slack=connected"))
}

#[utoipa::path(get, path = "/orgs/{org}/integrations/slack/channels", tag = "integrations", params(OrgPath),
    responses((status = 200, body = Vec<Channel>), (status = 404, body = Problem), (status = 429, body = Problem),
        (status = 502, body = Problem), (status = 503, body = Problem)))]
async fn slack_channels(
    State(ctx): State<AppContext>,
    scope: OrgScope,
) -> Result<Json<Vec<Channel>>, ApiError> {
    let kek = kek(&ctx)?;
    let slack = slack(&ctx);
    let chans =
        service::slack_channels(&ctx.db, kek.as_ref(), slack.as_ref(), scope.organisation_id)
            .await?;
    Ok(Json(chans))
}

#[derive(Serialize, ToSchema)]
pub struct Integration {
    pub id: Uuid,
    /// `slack`, `github`, `terraform`, `prometheus` or `k8s`.
    pub kind: String,
    /// `active`, `revoked` or `failing`.
    pub status: String,
    /// Slack workspace name.
    pub team_name: Option<String>,
    pub created_at: DateTime<FixedOffset>,
}

#[utoipa::path(get, path = "/orgs/{org}/integrations", tag = "integrations", params(OrgPath),
    responses((status = 200, body = Vec<Integration>), (status = 404, body = Problem)))]
async fn list(
    State(ctx): State<AppContext>,
    scope: OrgScope,
) -> Result<Json<Vec<Integration>>, ApiError> {
    let rows = service::list(&ctx.db, scope.organisation_id).await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| Integration {
                id: r.id,
                team_name: r.config["team_name"].as_str().map(str::to_owned),
                kind: r.kind,
                status: r.status,
                created_at: r.created_at,
            })
            .collect(),
    ))
}

#[utoipa::path(delete, path = "/orgs/{org}/integrations/{id}", tag = "integrations", params(OrgIdPath),
    responses((status = 204), (status = 403, body = Problem), (status = 404, body = Problem)))]
async fn remove(
    State(ctx): State<AppContext>,
    scope: OrgScope,
    Path((_, id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    scope.require_owner()?;
    let id: Uuid = id.parse().map_err(|_| ApiError::not_found())?;
    let (kek, slack) = (kek(&ctx)?, slack(&ctx));
    service::delete(
        &ctx.db,
        kek.as_ref(),
        slack.as_ref(),
        scope.organisation_id,
        scope.user_id,
        id,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn api() -> OpenApiRouter<AppContext> {
    OpenApiRouter::new()
        .routes(routes!(slack_start))
        .routes(routes!(slack_callback))
        .routes(routes!(slack_channels))
        .routes(routes!(list))
        .routes(routes!(remove))
}
