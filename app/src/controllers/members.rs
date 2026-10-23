use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, FixedOffset};
use loco_rs::app::AppContext;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::{OrgIdPath, OrgPath};
use crate::{
    api_error::ApiJson,
    api_error::{ApiError, Problem},
    middleware::{
        mailer,
        org_scope::{AuthUser, OrgScope},
    },
    models::_entities::{members, users},
    services::members as service,
    settings::Settings,
};

#[derive(Serialize, ToSchema)]
pub struct Member {
    pub id: Uuid,
    pub user_id: Uuid,
    pub email: String,
    pub name: Option<String>,
    pub role: String,
}

#[utoipa::path(get, path = "/orgs/{org}/members", tag = "members", params(OrgPath),
    responses((status = 200, body = Vec<Member>), (status = 404, body = Problem)))]
async fn list(
    State(ctx): State<AppContext>,
    scope: OrgScope,
) -> Result<Json<Vec<Member>>, ApiError> {
    let rows = members::Entity::find()
        .filter(members::Column::OrganisationId.eq(scope.organisation_id))
        .find_also_related(users::Entity)
        .all(&ctx.db)
        .await?;
    Ok(Json(
        rows.into_iter()
            .filter_map(|(m, u)| {
                u.map(|u| Member {
                    id: m.id,
                    user_id: u.id,
                    email: u.email,
                    name: u.name,
                    role: m.role,
                })
            })
            .collect(),
    ))
}

#[derive(Deserialize, ToSchema)]
pub struct NewInvite {
    pub email: String,
    /// `owner` or `member`.
    pub role: String,
}

#[derive(Serialize, ToSchema)]
pub struct Invite {
    pub id: Uuid,
    pub email: String,
    pub role: String,
    pub expires_at: DateTime<FixedOffset>,
}

#[utoipa::path(post, path = "/orgs/{org}/invites", tag = "members", params(OrgPath),
    request_body = NewInvite,
    responses((status = 201, body = Invite), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 422, body = Problem)))]
async fn invite(
    State(ctx): State<AppContext>,
    scope: OrgScope,
    ApiJson(body): ApiJson<NewInvite>,
) -> Result<(StatusCode, Json<Invite>), ApiError> {
    scope.require_owner()?;
    let web = Settings::get(&ctx).web_base_url;
    let row = service::invite(
        &ctx.db,
        mailer(&ctx).as_ref(),
        &web,
        scope.organisation_id,
        scope.user_id,
        &body.email,
        body.role,
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(Invite {
            id: row.id,
            email: row.email.as_str().into(),
            role: row.role.as_str().into(),
            expires_at: row.expires_at.fixed_offset(),
        }),
    ))
}

#[derive(Serialize, ToSchema)]
pub struct Membership {
    /// Organisation id.
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub role: String,
}

#[derive(IntoParams)]
#[into_params(parameter_in = Path)]
pub struct TokenPath {
    /// Invite token from the mail.
    pub token: String,
}

#[utoipa::path(post, path = "/invites/{token}/accept", tag = "members", params(TokenPath),
    responses((status = 200, body = Membership), (status = 401, body = Problem), (status = 403, body = Problem),
        (status = 410, body = Problem)))]
async fn accept(
    State(ctx): State<AppContext>,
    AuthUser(user_id): AuthUser,
    Path(token): Path<String>,
) -> Result<Json<Membership>, ApiError> {
    let (org, role) = service::accept(&ctx.db, user_id, &token).await?;
    Ok(Json(Membership {
        id: org.id,
        name: org.name,
        slug: org.slug,
        role: role.as_str().into(),
    }))
}

#[utoipa::path(delete, path = "/orgs/{org}/members/{id}", tag = "members", params(OrgIdPath),
    responses((status = 204), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 409, body = Problem)))]
async fn remove(
    State(ctx): State<AppContext>,
    scope: OrgScope,
    Path((_, member_id)): Path<(String, Uuid)>,
) -> Result<StatusCode, ApiError> {
    scope.require_owner()?;
    service::remove(&ctx.db, scope.organisation_id, scope.user_id, member_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn api() -> OpenApiRouter<AppContext> {
    OpenApiRouter::new()
        .routes(routes!(list))
        .routes(routes!(invite))
        .routes(routes!(remove))
        .routes(routes!(accept))
}
