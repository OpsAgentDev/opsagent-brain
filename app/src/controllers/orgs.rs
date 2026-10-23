use axum::{extract::State, http::StatusCode, Json};
use chrono::{DateTime, FixedOffset};
use loco_rs::app::AppContext;
use opsagent_core::org::{Organisation, OrganisationPatch};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::OrgPath;
use crate::{
    actions::orgs::CreateOrgInput,
    api_error::{ApiError, ApiJson, Problem},
    app::actions,
    middleware::org_scope::{AuthUser, OrgScope},
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
}

#[utoipa::path(post, path = "/orgs", tag = "orgs", request_body = NewOrg,
    responses((status = 201, body = Org), (status = 401, body = Problem), (status = 422, body = Problem),
        (status = 429, body = Problem)))]
async fn create_org(
    State(ctx): State<AppContext>,
    AuthUser(user_id): AuthUser,
    ApiJson(body): ApiJson<NewOrg>,
) -> Result<(StatusCode, Json<Org>), ApiError> {
    let input = CreateOrgInput {
        user_id,
        name: body.name,
        timezone: body.timezone.unwrap_or_else(|| "UTC".into()),
    };
    let org = actions(&ctx)?.orgs.create_org.run(input).await?;
    Ok((StatusCode::CREATED, Json(view(&org, "owner"))))
}

#[utoipa::path(get, path = "/orgs", tag = "orgs",
    responses((status = 200, body = Vec<Org>), (status = 401, body = Problem)))]
async fn list(
    State(ctx): State<AppContext>,
    AuthUser(user_id): AuthUser,
) -> Result<Json<Vec<Org>>, ApiError> {
    let rows = actions(&ctx)?.orgs.list_orgs.run(user_id).await?;
    Ok(Json(
        rows.iter().map(|(o, r)| view(o, r.as_str())).collect(),
    ))
}

#[utoipa::path(get, path = "/orgs/{org}", tag = "orgs", params(OrgPath),
    responses((status = 200, body = Org), (status = 404, body = Problem)))]
async fn show(State(ctx): State<AppContext>, scope: OrgScope) -> Result<Json<Org>, ApiError> {
    let org = actions(&ctx)?.orgs.get_org.run(&scope).await?;
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
    State(ctx): State<AppContext>,
    scope: OrgScope,
    ApiJson(body): ApiJson<OrgPatch>,
) -> Result<Json<Org>, ApiError> {
    let patch = OrganisationPatch {
        name: body.name,
        timezone: body.timezone,
    };
    let org = actions(&ctx)?.orgs.update_org.run(&scope, patch).await?;
    Ok(Json(view(&org, scope.member.role.as_str())))
}

#[utoipa::path(delete, path = "/orgs/{org}", tag = "orgs", params(OrgPath),
    responses((status = 204), (status = 403, body = Problem), (status = 404, body = Problem)))]
async fn delete(State(ctx): State<AppContext>, scope: OrgScope) -> Result<StatusCode, ApiError> {
    let actor = scope.member.user_id;
    actions(&ctx)?.orgs.delete_org.run(&scope, actor).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn api() -> OpenApiRouter<AppContext> {
    OpenApiRouter::new()
        .routes(routes!(create_org, list))
        .routes(routes!(show, update, delete))
}
