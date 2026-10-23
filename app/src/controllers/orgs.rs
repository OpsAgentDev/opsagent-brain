use axum::{extract::State, http::StatusCode, Json};
use chrono::{DateTime, FixedOffset};
use loco_rs::app::AppContext;
use opsagent_core::org::{valid_name, Organisation, OrganisationPatch, OrganisationsRepo};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::OrgPath;
use crate::{
    actions::DAY_SECS,
    adapters::db::Pg,
    api_error::{ApiError, ApiJson, Problem},
    app::kek,
    middleware::{
        org_scope::{AuthUser, OrgScope},
        rate_limiter,
    },
    services::orgs,
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

fn name(raw: &str) -> Result<String, ApiError> {
    valid_name(raw).map_err(ApiError::invalid)
}

fn valid_timezone(raw: &str) -> Result<String, ApiError> {
    raw.parse::<chrono_tz::Tz>()
        .map(|_| raw.into())
        .map_err(|_| ApiError::invalid("timezone must be an IANA name such as Europe/Berlin"))
}

#[derive(Deserialize, ToSchema)]
pub struct NewOrg {
    pub name: String,
    /// IANA zone; default `UTC`.
    pub timezone: Option<String>,
}

/// Organisations a user may create per day (each gets a DEK, and owners can send mail).
pub const ORGS_PER_USER_PER_DAY: i64 = 5;

/// Counts one creation for `user_id`; 429 `rate_limited` past the daily cap. Fails closed.
async fn limit_creation(ctx: &AppContext, user_id: Uuid) -> Result<(), ApiError> {
    let key = format!("ratelimit:org_create:user:{user_id}");
    let ok = rate_limiter(ctx)
        .hit(&key, ORGS_PER_USER_PER_DAY, DAY_SECS)
        .await?;
    if ok {
        Ok(())
    } else {
        // shortcut: Retry-After is the window length, an upper bound; read the key TTL if exactness matters.
        Err(ApiError::rate_limited(
            "At most 5 organisations can be created per day.",
            DAY_SECS.unsigned_abs(),
        ))
    }
}

#[utoipa::path(post, path = "/orgs", tag = "orgs", request_body = NewOrg,
    responses((status = 201, body = Org), (status = 401, body = Problem), (status = 422, body = Problem),
        (status = 429, body = Problem)))]
async fn create_org(
    State(ctx): State<AppContext>,
    AuthUser(user_id): AuthUser,
    ApiJson(body): ApiJson<NewOrg>,
) -> Result<(StatusCode, Json<Org>), ApiError> {
    let name = name(&body.name)?;
    let tz = valid_timezone(body.timezone.as_deref().unwrap_or("UTC"))?;
    limit_creation(&ctx, user_id).await?;
    let org = orgs::create(&ctx.db, kek(&ctx)?.as_ref(), user_id, &name, &tz).await?;
    Ok((StatusCode::CREATED, Json(view(&org, "owner"))))
}

#[utoipa::path(get, path = "/orgs", tag = "orgs",
    responses((status = 200, body = Vec<Org>), (status = 401, body = Problem)))]
async fn list(
    State(ctx): State<AppContext>,
    AuthUser(user_id): AuthUser,
) -> Result<Json<Vec<Org>>, ApiError> {
    let rows = Pg::new(&ctx.db).list_for_user(user_id).await?;
    Ok(Json(
        rows.iter().map(|(o, r)| view(o, r.as_str())).collect(),
    ))
}

async fn load(ctx: &AppContext, scope: &OrgScope) -> Result<Organisation, ApiError> {
    Pg::new(&ctx.db)
        .get(scope.organisation_id)
        .await?
        .ok_or_else(ApiError::not_found)
}

#[utoipa::path(get, path = "/orgs/{org}", tag = "orgs", params(OrgPath),
    responses((status = 200, body = Org), (status = 404, body = Problem)))]
async fn show(State(ctx): State<AppContext>, scope: OrgScope) -> Result<Json<Org>, ApiError> {
    Ok(Json(view(&load(&ctx, &scope).await?, &scope.role)))
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
    State(ctx): State<AppContext>,
    scope: OrgScope,
    ApiJson(body): ApiJson<OrgPatch>,
) -> Result<Json<Org>, ApiError> {
    scope.require_owner()?;
    let patch = OrganisationPatch {
        name: body.name.as_deref().map(name).transpose()?,
        timezone: body.timezone.as_deref().map(valid_timezone).transpose()?,
    };
    let org = Pg::new(&ctx.db)
        .update(scope.organisation_id, patch)
        .await?;
    Ok(Json(view(&org, &scope.role)))
}

#[utoipa::path(delete, path = "/orgs/{org}", tag = "orgs", params(OrgPath),
    responses((status = 204), (status = 403, body = Problem), (status = 404, body = Problem)))]
async fn delete(State(ctx): State<AppContext>, scope: OrgScope) -> Result<StatusCode, ApiError> {
    scope.require_owner()?;
    orgs::delete(&ctx.db, scope.organisation_id, scope.user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn api() -> OpenApiRouter<AppContext> {
    OpenApiRouter::new()
        .routes(routes!(create_org, list))
        .routes(routes!(show, update, delete))
}
