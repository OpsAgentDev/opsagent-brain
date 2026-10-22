use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Duration, FixedOffset, Utc};
use loco_rs::app::AppContext;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QuerySelect, Set, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::{OrgIdPath, OrgPath};
use crate::{
    api_error::{ApiError, ApiJson, Problem},
    mailers::magic_link as mail,
    middleware::{
        mailer,
        org_scope::{AuthUser, OrgScope},
    },
    models::{
        _entities::{invites, members, organisations, users},
        audit, magic_links,
        members::{self as member_model, MEMBER, OWNER},
        now,
        users::normalize_email,
    },
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
    let email = normalize_email(&body.email).ok_or_else(|| ApiError::invalid("invalid email"))?;
    if body.role != OWNER && body.role != MEMBER {
        return Err(ApiError::invalid("role must be owner or member"));
    }
    let org = organisations::Entity::find_by_id(scope.organisation_id)
        .one(&ctx.db)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let token = magic_links::new_token();
    let row = invites::ActiveModel {
        id: Set(Uuid::new_v4()),
        organisation_id: Set(org.id),
        email: Set(email.clone()),
        role: Set(body.role),
        token_hash: Set(magic_links::hash_token(&token)),
        expires_at: Set((Utc::now() + Duration::days(7)).into()),
        status: Set("pending".into()),
        created_at: Set(now()),
        updated_at: Set(now()),
    }
    .insert(&ctx.db)
    .await?;
    audit::record(
        &ctx.db,
        Some(org.id),
        scope.user_id,
        "invite.create",
        Some(("invite", row.id.to_string())),
    )
    .await?;
    let link = format!("{}/invites/{token}", Settings::get(&ctx).web_base_url);
    if let Err(e) = mailer(&ctx)
        .send(mail::invite(&email, &org.name, &link))
        .await
    {
        tracing::error!(error = %e, "invite mail failed");
    }
    Ok((
        StatusCode::CREATED,
        Json(Invite {
            id: row.id,
            email: row.email,
            role: row.role,
            expires_at: row.expires_at,
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
    let gone = || ApiError::gone("invite_invalid");
    let inv = invites::Entity::find()
        .filter(invites::Column::TokenHash.eq(magic_links::hash_token(&token)))
        .filter(invites::Column::Status.eq("pending"))
        .filter(invites::Column::ExpiresAt.gt(now()))
        .one(&ctx.db)
        .await?
        .ok_or_else(gone)?;
    let user = users::Entity::find_by_id(user_id)
        .one(&ctx.db)
        .await?
        .ok_or_else(ApiError::unauthenticated)?;
    if inv.email.to_lowercase() != user.email.to_lowercase() {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "invite_email_mismatch",
            "This invite was sent to a different email address.",
        ));
    }
    let org = organisations::Entity::find_by_id(inv.organisation_id)
        .filter(organisations::Column::DeletedAt.is_null())
        .one(&ctx.db)
        .await?
        .ok_or_else(gone)?;
    let txn = ctx.db.begin().await?;
    // Compare-and-set so a concurrent double accept consumes the invite once.
    let claimed = invites::Entity::update_many()
        .col_expr(invites::Column::Status, "accepted".into())
        .col_expr(invites::Column::UpdatedAt, now().into())
        .filter(invites::Column::Id.eq(inv.id))
        .filter(invites::Column::Status.eq("pending"))
        .exec(&txn)
        .await?;
    if claimed.rows_affected != 1 {
        return Err(gone());
    }
    let existing = members::Entity::find()
        .filter(members::Column::OrganisationId.eq(org.id))
        .filter(members::Column::UserId.eq(user_id))
        .one(&txn)
        .await?;
    let role = match existing {
        Some(m) => m.role,
        None => {
            member_model::add(&txn, org.id, user_id, &inv.role)
                .await?
                .role
        }
    };
    audit::record(
        &txn,
        Some(org.id),
        user_id,
        "invite.accept",
        Some(("invite", inv.id.to_string())),
    )
    .await?;
    txn.commit().await?;
    Ok(Json(Membership {
        id: org.id,
        name: org.name,
        slug: org.slug,
        role,
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
    let txn = ctx.db.begin().await?;
    // Serialise owner removals per org so two concurrent requests cannot orphan it.
    organisations::Entity::find_by_id(scope.organisation_id)
        .lock_exclusive()
        .one(&txn)
        .await?;
    let target = members::Entity::find_by_id(member_id)
        .filter(members::Column::OrganisationId.eq(scope.organisation_id))
        .one(&txn)
        .await?
        .ok_or_else(ApiError::not_found)?;
    if target.role == OWNER && member_model::owner_count(&txn, scope.organisation_id).await? <= 1 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "last_owner",
            "An organisation must keep at least one owner.",
        ));
    }
    members::Entity::delete_by_id(member_id).exec(&txn).await?;
    // A removed user must not be able to rejoin through a still-pending invite.
    if let Some(u) = users::Entity::find_by_id(target.user_id).one(&txn).await? {
        invites::Entity::update_many()
            .col_expr(invites::Column::Status, "cancelled".into())
            .col_expr(invites::Column::UpdatedAt, now().into())
            .filter(invites::Column::OrganisationId.eq(scope.organisation_id))
            .filter(invites::Column::Email.eq(u.email.to_lowercase()))
            .filter(invites::Column::Status.eq("pending"))
            .exec(&txn)
            .await?;
    }
    audit::record(
        &txn,
        Some(scope.organisation_id),
        scope.user_id,
        "member.remove",
        Some(("member", member_id.to_string())),
    )
    .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn api() -> OpenApiRouter<AppContext> {
    OpenApiRouter::new()
        .routes(routes!(list))
        .routes(routes!(invite))
        .routes(routes!(remove))
        .routes(routes!(accept))
}
