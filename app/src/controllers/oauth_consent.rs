//! `/v1/oauth/consent/{request_id}`: what web's consent page shows, and the member's answer.
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{AppendHeaders, IntoResponse},
    Json,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use crate::{
    actions::oauth::Decision,
    api_error::{ApiError, ApiJson, Problem},
    config::Config,
    middleware::org_scope::AuthUser,
    state::AppState,
};

const COOKIE_PREFIX: &str = "oa_consent_";

/// The `Set-Cookie` value that binds consent request `id` to the browser that started it
/// (`max_age` 0 removes it). Scoped to the consent endpoints, same domain as the session.
pub fn consent_cookie(c: &Config, id: Uuid, max_age: i64) -> String {
    let mut v = format!(
        "{COOKIE_PREFIX}{id}=1; Path=/v1/oauth/consent; HttpOnly; SameSite=Lax; Max-Age={max_age}"
    );
    if c.cookie_secure {
        v.push_str("; Secure");
    }
    if !c.cookie_domain.is_empty() {
        v.push_str(&format!("; Domain={}", c.cookie_domain));
    }
    v
}

/// 403 unless the request carries the cookie authorize set: a consent link opened in another
/// browser (for instance through a forged sign-in `return_to`) cannot be approved.
fn require_browser(headers: &HeaderMap, id: Uuid) -> Result<(), ApiError> {
    let want = format!("{COOKIE_PREFIX}{id}=1");
    let found = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .any(|c| c.trim() == want);
    if found {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "consent_wrong_browser",
            "Open the consent page in the browser where you started connecting the agent.",
        ))
    }
}

#[derive(IntoParams)]
#[into_params(parameter_in = Path)]
pub struct RequestPath {
    pub request_id: Uuid,
}

#[derive(Serialize, ToSchema)]
pub struct ConsentOrganisation {
    pub slug: String,
    pub name: String,
}

#[derive(Serialize, ToSchema)]
pub struct ConsentView {
    pub client_name: String,
    pub redirect_uri: String,
    /// Always false: dynamic and metadata-document clients are unverified.
    pub verified: bool,
    /// The redirect goes to this computer: warn the member.
    pub loopback: bool,
    pub organisations: Vec<ConsentOrganisation>,
}

#[utoipa::path(get, path = "/oauth/consent/{request_id}", tag = "oauth", params(RequestPath),
    responses((status = 200, body = ConsentView), (status = 401, body = Problem),
        (status = 403, body = Problem), (status = 410, body = Problem)))]
async fn show(
    State(app): State<AppState>,
    AuthUser(user_id): AuthUser,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ConsentView>, ApiError> {
    let id = id.parse().map_err(|_| ApiError::gone("consent_expired"))?;
    require_browser(&headers, id)?;
    let v = app
        .actions
        .oauth
        .get_consent
        .run(user_id, id, app.clock.now())
        .await?;
    Ok(Json(ConsentView {
        client_name: v.client_name,
        redirect_uri: v.redirect_uri,
        verified: v.verified,
        loopback: v.loopback,
        organisations: v
            .organisations
            .into_iter()
            .map(|(slug, name)| ConsentOrganisation { slug, name })
            .collect(),
    }))
}

#[derive(Deserialize, ToSchema)]
pub struct ConsentDecision {
    /// Slug of the organisation to grant access to; required unless `deny`.
    pub organisation: Option<String>,
    pub deny: Option<bool>,
}

#[derive(Serialize, ToSchema)]
pub struct ConsentRedirect {
    /// The client's redirect URI with `code` or `error`, `state` and `iss`.
    pub redirect_to: String,
}

#[utoipa::path(post, path = "/oauth/consent/{request_id}", tag = "oauth", params(RequestPath),
    request_body = ConsentDecision,
    responses((status = 200, body = ConsentRedirect), (status = 401, body = Problem),
        (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 410, body = Problem), (status = 422, body = Problem)))]
async fn decide(
    State(app): State<AppState>,
    AuthUser(user_id): AuthUser,
    headers: HeaderMap,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<ConsentDecision>,
) -> Result<impl IntoResponse, ApiError> {
    let id = id.parse().map_err(|_| ApiError::gone("consent_expired"))?;
    require_browser(&headers, id)?;
    let decision = match (body.deny, body.organisation) {
        (Some(true), _) => Decision::Deny,
        (_, Some(slug)) => Decision::Approve(slug),
        _ => return Err(ApiError::invalid("Choose an organisation or deny.")),
    };
    let redirect_to = app
        .actions
        .oauth
        .decide_consent
        .run(user_id, id, decision, app.clock.now())
        .await?;
    let clear = AppendHeaders([(header::SET_COOKIE, consent_cookie(&app.config, id, 0))]);
    Ok((clear, Json(ConsentRedirect { redirect_to })))
}

pub fn api() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(show, decide))
}
