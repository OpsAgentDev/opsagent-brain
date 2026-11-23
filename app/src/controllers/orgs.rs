use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, FixedOffset};
use opsagent_core::org::{Organisation, OrganisationPatch, SignupSource};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::OrgPath;
use crate::{
    actions::orgs::{AuditItem, CreateOrgInput},
    api_error::{ApiError, ApiJson, ApiQuery, Problem},
    middleware::org_scope::{AuthUser, OrgScope},
    state::AppState,
    views::page::{page_request, Page, PageParams},
};

#[derive(Serialize, ToSchema)]
pub struct Org {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub timezone: String,
    /// The caller's role: `owner` or `member`.
    pub role: String,
    pub created_at: DateTime<FixedOffset>,
}

fn view(o: &Organisation, role: &str) -> Org {
    Org {
        id: o.id,
        name: o.name.clone(),
        slug: o.slug.clone(),
        timezone: o.timezone.clone(),
        role: role.into(),
        created_at: o.created_at.fixed_offset(),
    }
}

#[derive(Deserialize, ToSchema)]
pub struct NewOrg {
    pub name: String,
    /// IANA zone; default `UTC`.
    pub timezone: Option<String>,
    /// Where the sign-up came from; each value is cut to 200 characters.
    pub source: Option<SignupSourceBody>,
}

#[derive(Deserialize, ToSchema)]
pub struct SignupSourceBody {
    pub utm_source: Option<String>,
    pub utm_medium: Option<String>,
    pub utm_campaign: Option<String>,
    pub referrer: Option<String>,
    pub landing_path: Option<String>,
}

impl From<SignupSourceBody> for SignupSource {
    fn from(b: SignupSourceBody) -> Self {
        Self {
            utm_source: b.utm_source,
            utm_medium: b.utm_medium,
            utm_campaign: b.utm_campaign,
            referrer: b.referrer,
            landing_path: b.landing_path,
        }
    }
}

#[utoipa::path(post, path = "/orgs", tag = "orgs", request_body = NewOrg,
    responses((status = 201, body = Org), (status = 401, body = Problem), (status = 422, body = Problem),
        (status = 429, body = Problem)))]
async fn create_org(
    State(app): State<AppState>,
    AuthUser(user_id): AuthUser,
    ApiJson(body): ApiJson<NewOrg>,
) -> Result<(StatusCode, Json<Org>), ApiError> {
    let input = CreateOrgInput {
        user_id,
        name: body.name,
        timezone: body.timezone.unwrap_or_else(|| "UTC".into()),
        source: body.source.map(Into::into),
    };
    let org = app.actions.orgs.create_org.run(input).await?;
    Ok((StatusCode::CREATED, Json(view(&org, "owner"))))
}

#[utoipa::path(get, path = "/orgs", tag = "orgs",
    responses((status = 200, body = Vec<Org>), (status = 401, body = Problem)))]
async fn list(
    State(app): State<AppState>,
    AuthUser(user_id): AuthUser,
) -> Result<Json<Vec<Org>>, ApiError> {
    let rows = app.actions.orgs.list_orgs.run(user_id).await?;
    Ok(Json(
        rows.iter().map(|(o, r)| view(o, r.as_str())).collect(),
    ))
}

#[utoipa::path(get, path = "/orgs/{org}", tag = "orgs", params(OrgPath),
    responses((status = 200, body = Org), (status = 404, body = Problem)))]
async fn show(State(app): State<AppState>, scope: OrgScope) -> Result<Json<Org>, ApiError> {
    let org = app.actions.orgs.get_org.run(&scope).await?;
    Ok(Json(view(&org, scope.member.role.as_str())))
}

#[derive(Deserialize, ToSchema)]
pub struct OrgPatch {
    pub name: Option<String>,
    pub timezone: Option<String>,
}

#[utoipa::path(patch, path = "/orgs/{org}", tag = "orgs", params(OrgPath), request_body = OrgPatch,
    responses((status = 200, body = Org), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 422, body = Problem)))]
async fn update(
    State(app): State<AppState>,
    scope: OrgScope,
    ApiJson(body): ApiJson<OrgPatch>,
) -> Result<Json<Org>, ApiError> {
    let patch = OrganisationPatch {
        name: body.name,
        timezone: body.timezone,
    };
    let org = app.actions.orgs.update_org.run(&scope, patch).await?;
    Ok(Json(view(&org, scope.member.role.as_str())))
}

#[utoipa::path(delete, path = "/orgs/{org}", tag = "orgs", params(OrgPath),
    responses((status = 204), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 502, body = Problem, description = "`billing_unavailable`: Stripe could not cancel the subscription")))]
async fn delete(State(app): State<AppState>, scope: OrgScope) -> Result<StatusCode, ApiError> {
    let actor = scope.member.user_id;
    app.actions.orgs.delete_org.run(&scope, actor).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// One audit log entry.
#[derive(Serialize, ToSchema)]
pub struct AuditEntry {
    pub id: Uuid,
    pub at: DateTime<FixedOffset>,
    /// `member`, `agent` or `system`.
    pub actor_type: String,
    /// A member's name and email (`Former member` once they left), `agent <client name>`, or
    /// `OpsAgent` for the system.
    pub actor: String,
    /// Stable action code, e.g. `connection.create`.
    pub action: String,
    /// What the action was on (`connection`, `member`, `finding`, ...); null without a target.
    pub target_type: Option<String>,
    /// The target by name, where it has one and still exists.
    pub target: Option<String>,
    pub outcome: Option<String>,
    /// The entry's metadata with anything secret-like left out.
    #[schema(value_type = Object)]
    pub metadata: serde_json::Value,
}

fn audit_view(i: AuditItem) -> AuditEntry {
    AuditEntry {
        id: i.id,
        at: i.at.fixed_offset(),
        actor_type: i.actor_type.into(),
        actor: i.actor,
        action: i.action,
        target_type: i.target_type,
        target: i.target,
        outcome: i.outcome,
        metadata: i.metadata,
    }
}

/// The organisation's audit log, newest first. Owners only.
#[utoipa::path(get, path = "/orgs/{org}/audit", tag = "orgs", params(OrgPath, PageParams),
    responses((status = 200, body = Page<AuditEntry>), (status = 403, body = Problem),
        (status = 404, body = Problem), (status = 422, body = Problem)))]
async fn audit(
    State(app): State<AppState>,
    scope: OrgScope,
    ApiQuery(p): ApiQuery<PageParams>,
) -> Result<Json<Page<AuditEntry>>, ApiError> {
    let list = &app.actions.orgs.list_audit;
    let page = list.run(&scope, page_request(&p)?).await?;
    Ok(Json(Page::of(page).map(audit_view)))
}

/// The organisation's own data as one JSON document, sent as an attachment: `organisation`,
/// `members`, `connections`, `findings` (with stored evidence), `delivery_settings`,
/// `recipients`, `deliveries` and `audit_log`. Owners only; once per organisation per hour.
#[utoipa::path(post, path = "/orgs/{org}/export", tag = "orgs", params(OrgPath),
    responses((status = 200, content_type = "application/json", body = Object,
            description = "The export document (`Content-Disposition: attachment`)"),
        (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 413, body = Problem, description = "`export_too_large`: over 20 MB; contact support"),
        (status = 429, body = Problem)))]
async fn export(
    State(app): State<AppState>,
    scope: OrgScope,
) -> Result<impl IntoResponse, ApiError> {
    let bytes = app.actions.orgs.export_org.run(&scope).await?;
    // A slug is lowercase ASCII, digits and dashes: safe inside the quoted filename.
    let name = format!("opsagent-export-{}.json", scope.organisation.slug);
    Ok((
        [
            (header::CONTENT_TYPE, "application/json".to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{name}\""),
            ),
            (header::CACHE_CONTROL, "no-store".to_owned()),
        ],
        bytes,
    ))
}

pub fn api() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(create_org, list))
        .routes(routes!(show, update, delete))
        .routes(routes!(audit))
        .routes(routes!(export))
}
