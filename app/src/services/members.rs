//! Membership use cases: invite, accept (bound to the invited email), remove (never the last
//! owner).
use axum::http::StatusCode;
use chrono::{Duration, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QuerySelect, Set,
    TransactionTrait,
};
use uuid::Uuid;

use crate::{
    api_error::ApiError,
    mailers::{magic_link as mail, Mailer},
    models::{
        _entities::{invites, members, organisations, users},
        audit, magic_links,
        members::{self as member_model, MEMBER, OWNER},
        now,
        users::normalize_email,
    },
};

/// Creates a 7-day invite and mails its link (`{web_base_url}/invites/{token}`).
pub async fn invite(
    db: &DatabaseConnection,
    mailer: &dyn Mailer,
    web_base_url: &str,
    organisation_id: Uuid,
    actor: Uuid,
    email: &str,
    role: String,
) -> Result<invites::Model, ApiError> {
    let email = normalize_email(email).ok_or_else(|| ApiError::invalid("invalid email"))?;
    if role != OWNER && role != MEMBER {
        return Err(ApiError::invalid("role must be owner or member"));
    }
    let org = organisations::Entity::find_by_id(organisation_id)
        .one(db)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let token = magic_links::new_token();
    let txn = db.begin().await?;
    let row = invites::ActiveModel {
        id: Set(Uuid::new_v4()),
        organisation_id: Set(org.id),
        email: Set(email.clone()),
        role: Set(role),
        token_hash: Set(magic_links::hash_token(&token)),
        expires_at: Set((Utc::now() + Duration::days(7)).into()),
        status: Set("pending".into()),
        created_at: Set(now()),
        updated_at: Set(now()),
    }
    .insert(&txn)
    .await?;
    audit::record(
        &txn,
        Some(org.id),
        actor,
        "invite.create",
        Some(("invite", row.id.to_string())),
    )
    .await?;
    txn.commit().await?;
    let link = format!("{web_base_url}/invites/{token}");
    if let Err(e) = mailer.send(mail::invite(&email, &org.name, &link)).await {
        tracing::error!(error = %e, "invite mail failed");
    }
    Ok(row)
}

/// Accepts invite `token` for signed-in `user_id`; returns the organisation and the role held.
pub async fn accept(
    db: &DatabaseConnection,
    user_id: Uuid,
    token: &str,
) -> Result<(organisations::Model, String), ApiError> {
    let gone = || ApiError::gone("invite_invalid");
    let inv = invites::Entity::find()
        .filter(invites::Column::TokenHash.eq(magic_links::hash_token(token)))
        .filter(invites::Column::Status.eq("pending"))
        .filter(invites::Column::ExpiresAt.gt(now()))
        .one(db)
        .await?
        .ok_or_else(gone)?;
    let user = users::Entity::find_by_id(user_id)
        .one(db)
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
        .one(db)
        .await?
        .ok_or_else(gone)?;
    let txn = db.begin().await?;
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
    Ok((org, role))
}

/// Removes member `member_id` for owner `actor`; `last_owner` if it would leave no owner.
pub async fn remove(
    db: &DatabaseConnection,
    organisation_id: Uuid,
    actor: Uuid,
    member_id: Uuid,
) -> Result<(), ApiError> {
    let txn = db.begin().await?;
    // Serialise owner removals per org so two concurrent requests cannot orphan it.
    organisations::Entity::find_by_id(organisation_id)
        .lock_exclusive()
        .one(&txn)
        .await?;
    let target = members::Entity::find_by_id(member_id)
        .filter(members::Column::OrganisationId.eq(organisation_id))
        .one(&txn)
        .await?
        .ok_or_else(ApiError::not_found)?;
    if target.role == OWNER && member_model::owner_count(&txn, organisation_id).await? <= 1 {
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
            .filter(invites::Column::OrganisationId.eq(organisation_id))
            .filter(invites::Column::Email.eq(u.email.to_lowercase()))
            .filter(invites::Column::Status.eq("pending"))
            .exec(&txn)
            .await?;
    }
    audit::record(
        &txn,
        Some(organisation_id),
        actor,
        "member.remove",
        Some(("member", member_id.to_string())),
    )
    .await?;
    txn.commit().await?;
    Ok(())
}
