use axum::{extract::State, http::StatusCode, Json};
use chrono::{DateTime, FixedOffset};
use loco_rs::app::AppContext;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::OrgPath;
use crate::{
    api_error::{ApiError, ApiJson, Problem},
    app::kek,
    middleware::org_scope::{AuthUser, OrgScope},
    models::{
        _entities::{members, organisations},
        now,
        organisations::{valid_name, valid_timezone},
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

fn view(o: &organisations::Model, role: &str) -> Org {
    Org {
        id: o.id,
        name: o.name.clone(),
        slug: o.slug.clone(),
        timezone: o.timezone.clone(),
        role: role.into(),
        created_at: o.created_at,
    }
}

#[derive(Deserialize, ToSchema)]
pub struct NewOrg {
    pub name: String,
    /// IANA zone; default `UTC`.
    pub timezone: Option<String>,
}

#[utoipa::path(post, path = "/orgs", tag = "orgs", request_body = NewOrg,
    responses((status = 201, body = Org), (status = 401, body = Problem), (status = 422, body = Problem)))]
async fn create_org(
    State(ctx): State<AppContext>,
    AuthUser(user_id): AuthUser,
    ApiJson(body): ApiJson<NewOrg>,
) -> Result<(StatusCode, Json<Org>), ApiError> {
    let name = valid_name(&body.name)?;
    let tz = valid_timezone(body.timezone.as_deref().unwrap_or("UTC"))?;
    let org = orgs::create(&ctx.db, kek(&ctx)?.as_ref(), user_id, &name, &tz).await?;
    Ok((StatusCode::CREATED, Json(view(&org, "owner"))))
}

#[utoipa::path(get, path = "/orgs", tag = "orgs",
    responses((status = 200, body = Vec<Org>), (status = 401, body = Problem)))]
async fn list(
    State(ctx): State<AppContext>,
    AuthUser(user_id): AuthUser,
) -> Result<Json<Vec<Org>>, ApiError> {
    // tenancy: the caller's own memberships, across organisations.
    let rows = members::Entity::find()
        .filter(members::Column::UserId.eq(user_id))
        .find_also_related(organisations::Entity)
        .all(&ctx.db)
        .await?;
    Ok(Json(
        rows.iter()
            .filter_map(|(m, o)| {
                o.as_ref()
                    .filter(|o| o.deleted_at.is_none())
                    .map(|o| view(o, &m.role))
            })
            .collect(),
    ))
}

async fn load(ctx: &AppContext, scope: &OrgScope) -> Result<organisations::Model, ApiError> {
    organisations::Entity::find_by_id(scope.organisation_id)
        .one(&ctx.db)
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
    let mut a: organisations::ActiveModel = load(&ctx, &scope).await?.into();
    if let Some(n) = &body.name {
        a.name = Set(valid_name(n)?);
    }
    if let Some(t) = &body.timezone {
        a.timezone = Set(valid_timezone(t)?);
    }
    a.updated_at = Set(now());
    let org = a.update(&ctx.db).await?;
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
