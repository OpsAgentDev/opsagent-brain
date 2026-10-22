use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::{Duration, Utc};
use loco_rs::{
    app::AppContext,
    controller::Routes,
    prelude::{delete, get, post},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QuerySelect, Set, TransactionTrait,
};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    api_error::{ApiError, ApiJson},
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

async fn list(
    State(ctx): State<AppContext>,
    scope: OrgScope,
) -> Result<Json<Vec<Value>>, ApiError> {
    let rows = members::Entity::find()
        .filter(members::Column::OrganisationId.eq(scope.organisation_id))
        .find_also_related(users::Entity)
        .all(&ctx.db)
        .await?;
    Ok(Json(
        rows.into_iter()
            .filter_map(|(m, u)| {
                u.map(|u| json!({ "id": m.id, "user_id": u.id, "email": u.email, "name": u.name, "role": m.role }))
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
struct NewInvite {
    email: String,
    role: String,
}

async fn invite(
    State(ctx): State<AppContext>,
    scope: OrgScope,
    ApiJson(body): ApiJson<NewInvite>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
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
        Json(
            json!({ "id": row.id, "email": row.email, "role": row.role, "expires_at": row.expires_at }),
        ),
    ))
}

async fn accept(
    State(ctx): State<AppContext>,
    AuthUser(user_id): AuthUser,
    Path(token): Path<String>,
) -> Result<Json<Value>, ApiError> {
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
    Ok(Json(
        json!({ "id": org.id, "name": org.name, "slug": org.slug, "role": role }),
    ))
}

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

pub fn routes() -> Routes {
    Routes::new()
        .prefix("/v1")
        .add("/orgs/{org}/members", get(list))
        .add("/orgs/{org}/invites", post(invite))
        .add("/orgs/{org}/members/{id}", delete(remove))
        .add("/invites/{token}/accept", post(accept))
}
