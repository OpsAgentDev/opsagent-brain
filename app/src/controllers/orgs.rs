use axum::{extract::State, http::StatusCode, Json};
use loco_rs::{
    app::AppContext,
    controller::Routes,
    prelude::{get, post},
};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    api_error::{ApiError, ApiJson},
    middleware::org_scope::{AuthUser, OrgScope},
    models::{
        _entities::{members, organisations},
        audit, now,
        organisations::{create, valid_name, valid_timezone},
    },
};

fn view(o: &organisations::Model, role: &str) -> Value {
    json!({
        "id": o.id, "name": o.name, "slug": o.slug, "timezone": o.timezone,
        "role": role, "created_at": o.created_at,
    })
}

#[derive(Deserialize)]
struct NewOrg {
    name: String,
    timezone: Option<String>,
}

async fn create_org(
    State(ctx): State<AppContext>,
    AuthUser(user_id): AuthUser,
    ApiJson(body): ApiJson<NewOrg>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let name = valid_name(&body.name)?;
    let tz = valid_timezone(body.timezone.as_deref().unwrap_or("UTC"))?;
    let org = create(&ctx.db, user_id, &name, &tz).await?;
    Ok((StatusCode::CREATED, Json(view(&org, "owner"))))
}

async fn list(
    State(ctx): State<AppContext>,
    AuthUser(user_id): AuthUser,
) -> Result<Json<Vec<Value>>, ApiError> {
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

async fn show(State(ctx): State<AppContext>, scope: OrgScope) -> Result<Json<Value>, ApiError> {
    Ok(Json(view(&load(&ctx, &scope).await?, &scope.role)))
}

#[derive(Deserialize)]
struct OrgPatch {
    name: Option<String>,
    timezone: Option<String>,
}

async fn update(
    State(ctx): State<AppContext>,
    scope: OrgScope,
    ApiJson(body): ApiJson<OrgPatch>,
) -> Result<Json<Value>, ApiError> {
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

async fn delete(State(ctx): State<AppContext>, scope: OrgScope) -> Result<StatusCode, ApiError> {
    scope.require_owner()?;
    // TODO(billing): cancel the Stripe subscription before marking the org deleted.
    let mut a: organisations::ActiveModel = load(&ctx, &scope).await?.into();
    a.deleted_at = Set(Some(now()));
    a.updated_at = Set(now());
    a.update(&ctx.db).await?;
    audit::record(
        &ctx.db,
        Some(scope.organisation_id),
        scope.user_id,
        "org.delete",
        Some(("organisation", scope.organisation_id.to_string())),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn routes() -> Routes {
    Routes::new()
        .prefix("/v1/orgs")
        .add("/", post(create_org).get(list))
        .add("/{org}", get(show).patch(update).delete(delete))
}
