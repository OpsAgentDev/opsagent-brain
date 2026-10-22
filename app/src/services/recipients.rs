//! Email recipients of deliveries: owner adds (an email confirms by link, a member is active at
//! once), public confirm and unsubscribe by single-use token (only SHA-256 hashes are stored).
use axum::http::StatusCode;
use chrono::{Duration, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter, Set,
    SqlErr, TransactionTrait,
};
use uuid::Uuid;

use crate::{
    api_error::ApiError,
    mailers::{magic_link as mail, Mailer},
    models::{
        _entities::{
            connections, members, organisations,
            recipients::{self, Column as C},
            users,
        },
        audit, find_in_org,
        magic_links::{hash_token, new_token},
        now,
        users::normalize_email,
    },
};

pub const PENDING: &str = "pending";
pub const ACTIVE: &str = "active";
const CONFIRM_DAYS: i64 = 7;

/// Who to add: exactly one of `email` (confirms by mail) or `member_id`.
pub struct NewRecipient {
    pub email: Option<String>,
    pub member_id: Option<Uuid>,
    pub connection_id: Option<Uuid>,
}

/// The member's email, for a member of `organisation_id`.
async fn member_email(
    db: &DatabaseConnection,
    organisation_id: Uuid,
    member_id: Uuid,
) -> Result<String, ApiError> {
    let found = members::Entity::find_by_id(member_id)
        .filter(members::Column::OrganisationId.eq(organisation_id))
        .find_also_related(users::Entity)
        .one(db)
        .await?;
    match found {
        Some((_, Some(u))) => Ok(u.email.to_lowercase()),
        _ => Err(ApiError::invalid(
            "member_id is not a member of this organisation",
        )),
    }
}

fn is_duplicate(e: &DbErr) -> bool {
    matches!(e.sql_err(), Some(SqlErr::UniqueConstraintViolation(_)))
}

// shortcut: ~55 lines, one use case in one transaction plus its mail; split if it gains steps.
/// Adds a recipient for owner `actor`; mails the confirm link (`{web}/recipients/confirm?token=`)
/// to an email recipient. 409 `recipient_exists` for the same email and connection.
pub async fn create(
    db: &DatabaseConnection,
    mailer: &dyn Mailer,
    web_base_url: &str,
    organisation_id: Uuid,
    actor: Uuid,
    new: NewRecipient,
) -> Result<recipients::Model, ApiError> {
    let (email, member_id) = match (new.email.as_deref(), new.member_id) {
        (Some(e), None) => (
            normalize_email(e).ok_or_else(|| ApiError::invalid("invalid email"))?,
            None,
        ),
        (None, Some(m)) => (member_email(db, organisation_id, m).await?, Some(m)),
        _ => return Err(ApiError::invalid("give exactly one of email or member_id")),
    };
    if let Some(c) = new.connection_id {
        find_in_org::<connections::Entity>(
            db,
            connections::Column::OrganisationId,
            organisation_id,
            &c.to_string(),
        )
        .await?;
    }
    let token = member_id.is_none().then(new_token);
    let txn = db.begin().await?;
    let row = recipients::ActiveModel {
        id: Set(Uuid::new_v4()),
        organisation_id: Set(organisation_id),
        connection_id: Set(new.connection_id),
        email: Set(email.clone()),
        member_id: Set(member_id),
        status: Set(if token.is_some() { PENDING } else { ACTIVE }.into()),
        confirm_token_hash: Set(token.as_deref().map(hash_token)),
        confirm_expires_at: Set(token
            .as_ref()
            .map(|_| (Utc::now() + Duration::days(CONFIRM_DAYS)).into())),
        unsubscribe_token_hash: Set(None),
        unsubscribed_at: Set(None),
        created_at: Set(now()),
        updated_at: Set(now()),
    }
    .insert(&txn)
    .await
    .map_err(|e| {
        if is_duplicate(&e) {
            ApiError::new(
                StatusCode::CONFLICT,
                "recipient_exists",
                "This recipient is already added.",
            )
        } else {
            e.into()
        }
    })?;
    audit::record(
        &txn,
        Some(organisation_id),
        actor,
        "recipient.create",
        Some(("recipient", row.id.to_string())),
    )
    .await?;
    txn.commit().await?;
    if let Some(token) = token {
        let org = organisations::Entity::find_by_id(organisation_id)
            .one(db)
            .await?;
        let name = org.map(|o| o.name).unwrap_or_default();
        let link = format!("{web_base_url}/recipients/confirm?token={token}");
        if mailer
            .send(mail::recipient_confirm(&email, &name, &link))
            .await
            .is_err()
        {
            tracing::error!(error_code = "mail_failed", "recipient confirm mail failed");
        }
    }
    Ok(row)
}

/// Activates the pending recipient holding confirm `token`; 410 if unknown, used or expired.
pub async fn confirm(db: &DatabaseConnection, token: &str) -> Result<(), ApiError> {
    // tenancy: the token is the lookup key; the row names its organisation.
    let row = recipients::Entity::find()
        .filter(C::ConfirmTokenHash.eq(hash_token(token)))
        .filter(C::Status.eq(PENDING))
        .filter(C::ConfirmExpiresAt.gt(now()))
        .one(db)
        .await?
        .ok_or_else(|| ApiError::gone("recipient_token_invalid"))?;
    let txn = db.begin().await?;
    let done = recipients::Entity::update_many()
        .col_expr(C::Status, ACTIVE.into())
        .col_expr(C::ConfirmTokenHash, Option::<String>::None.into())
        .col_expr(
            C::ConfirmExpiresAt,
            Option::<chrono::DateTime<chrono::FixedOffset>>::None.into(),
        )
        .col_expr(C::UpdatedAt, now().into())
        .filter(C::OrganisationId.eq(row.organisation_id))
        .filter(C::Id.eq(row.id))
        .filter(C::Status.eq(PENDING))
        .exec(&txn)
        .await?;
    if done.rows_affected != 1 {
        return Err(ApiError::gone("recipient_token_invalid"));
    }
    audit::record_system(
        &txn,
        row.organisation_id,
        "recipient.confirm",
        ("recipient", row.id.to_string()),
        "success",
        serde_json::json!({}),
    )
    .await?;
    txn.commit().await?;
    Ok(())
}

/// A fresh unsubscribe token for the recipient's next mail footer; earlier tokens stop working.
pub async fn issue_unsubscribe_token(
    db: &DatabaseConnection,
    organisation_id: Uuid,
    id: Uuid,
) -> Result<String, ApiError> {
    let token = new_token();
    let set = recipients::Entity::update_many()
        .col_expr(C::UnsubscribeTokenHash, Some(hash_token(&token)).into())
        .col_expr(C::UpdatedAt, now().into())
        .filter(C::OrganisationId.eq(organisation_id))
        .filter(C::Id.eq(id))
        .filter(C::UnsubscribedAt.is_null())
        .exec(db)
        .await?;
    if set.rows_affected != 1 {
        return Err(ApiError::not_found());
    }
    Ok(token)
}

/// Unsubscribes the recipient holding `token` (single use); 410 if unknown or used.
pub async fn unsubscribe(db: &DatabaseConnection, token: &str) -> Result<(), ApiError> {
    let gone = || ApiError::gone("unsubscribe_token_invalid");
    // tenancy: the token is the lookup key; the row names its organisation.
    let row = recipients::Entity::find()
        .filter(C::UnsubscribeTokenHash.eq(hash_token(token)))
        .filter(C::UnsubscribedAt.is_null())
        .one(db)
        .await?
        .ok_or_else(gone)?;
    let txn = db.begin().await?;
    let done = recipients::Entity::update_many()
        .col_expr(C::UnsubscribedAt, Some(now()).into())
        .col_expr(C::UnsubscribeTokenHash, Option::<String>::None.into())
        .col_expr(C::UpdatedAt, now().into())
        .filter(C::OrganisationId.eq(row.organisation_id))
        .filter(C::Id.eq(row.id))
        .filter(C::UnsubscribedAt.is_null())
        .exec(&txn)
        .await?;
    if done.rows_affected != 1 {
        return Err(gone());
    }
    audit::record_system(
        &txn,
        row.organisation_id,
        "recipient.unsubscribe",
        ("recipient", row.id.to_string()),
        "success",
        serde_json::json!({}),
    )
    .await?;
    txn.commit().await?;
    Ok(())
}

/// Removes recipient `id` for owner `actor`.
pub async fn delete(
    db: &DatabaseConnection,
    organisation_id: Uuid,
    actor: Uuid,
    id: Uuid,
) -> Result<(), ApiError> {
    let txn = db.begin().await?;
    let gone = recipients::Entity::delete_many()
        .filter(C::OrganisationId.eq(organisation_id))
        .filter(C::Id.eq(id))
        .exec(&txn)
        .await?;
    if gone.rows_affected != 1 {
        return Err(ApiError::not_found());
    }
    audit::record(
        &txn,
        Some(organisation_id),
        actor,
        "recipient.delete",
        Some(("recipient", id.to_string())),
    )
    .await?;
    txn.commit().await?;
    Ok(())
}
