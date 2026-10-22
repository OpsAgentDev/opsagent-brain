//! Email recipients of deliveries: owner adds (an email confirms by link, a member is active at
//! once), public confirm by single-use token (SHA-256 at rest), and unsubscribe by a stable
//! HMAC token. Confirm mails are capped per address and per organisation, and never go to a
//! suppressed address; a capped or suppressed mail is answered as if sent.
use axum::http::StatusCode;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use chrono::{Duration, Utc};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use opsagent_ledger::redis;
use sea_orm::{
    sea_query::OnConflict, ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait,
    DatabaseConnection, DbErr, EntityTrait, QueryFilter, Set, SqlErr, TransactionTrait,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    api_error::ApiError,
    mailers::{magic_link as mail, Mailer},
    models::{
        _entities::{
            connections,
            email_suppressions::{self, Column as S},
            members, organisations,
            recipients::{self, Column as C},
            users,
        },
        audit, find_in_org,
        magic_links::{hash_token, new_token},
        now,
        users::normalize_email,
    },
    services::rate_limit::{hit, DAY_SECS},
};

pub const PENDING: &str = "pending";
pub const ACTIVE: &str = "active";
const CONFIRM_DAYS: i64 = 7;
/// Confirm mails per address per day.
pub const MAILS_PER_ADDRESS: i64 = 3;
/// Confirm mails per organisation per day.
pub const MAILS_PER_ORG: i64 = 20;
/// Unconfirmed confirm mails per (org, address) in 30 days before the address is suppressed as
/// `ignored` for that organisation.
pub const UNCONFIRMED_CAP: i64 = 2;
const UNCONFIRMED_WINDOW_SECS: i64 = 30 * DAY_SECS;

/// Hex SHA-256 of the lowercased address: the suppression key (no plaintext email stored).
pub fn email_hash(email: &str) -> String {
    format!("{:x}", Sha256::digest(email.to_lowercase()))
}

/// Unconfirmed confirm mails are counted per (organisation, address).
fn unconfirmed_key(organisation_id: Uuid, hash: &str) -> String {
    format!("recipient_confirm:unconfirmed:{organisation_id}:{hash}")
}

/// Days an `ignored` suppression lasts.
pub const IGNORED_DAYS: i64 = 90;

/// Records a global `unsubscribed` suppression (kept if present).
async fn suppress_unsubscribed(db: &impl ConnectionTrait, hash: String) -> Result<(), DbErr> {
    let row = email_suppressions::ActiveModel {
        id: Set(Uuid::new_v4()),
        organisation_id: Set(None),
        email_hash: Set(hash),
        reason: Set("unsubscribed".into()),
        expires_at: Set(None),
        created_at: Set(now()),
    };
    upsert(
        db,
        row,
        OnConflict::columns([S::OrganisationId, S::EmailHash])
            .do_nothing()
            .to_owned(),
    )
    .await
}

/// Records (or renews) a 90-day `ignored` suppression for `organisation_id` only.
async fn suppress_ignored(
    db: &impl ConnectionTrait,
    organisation_id: Uuid,
    hash: String,
) -> Result<(), DbErr> {
    let row = email_suppressions::ActiveModel {
        id: Set(Uuid::new_v4()),
        organisation_id: Set(Some(organisation_id)),
        email_hash: Set(hash),
        reason: Set("ignored".into()),
        expires_at: Set(Some((Utc::now() + Duration::days(IGNORED_DAYS)).into())),
        created_at: Set(now()),
    };
    let renew = OnConflict::columns([S::OrganisationId, S::EmailHash])
        .update_column(S::ExpiresAt)
        .to_owned();
    upsert(db, row, renew).await
}

async fn upsert(
    db: &impl ConnectionTrait,
    row: email_suppressions::ActiveModel,
    on: OnConflict,
) -> Result<(), DbErr> {
    email_suppressions::Entity::insert(row)
        .on_conflict(on)
        .exec_without_returning(db)
        .await
        .map(|_| ())
}

/// Whether mail from `organisation_id` to `email` is suppressed: a global unsubscribe, or an
/// unexpired `ignored` row for that organisation. Every delivery mail checks this.
pub async fn is_suppressed(
    db: &impl ConnectionTrait,
    organisation_id: Uuid,
    email: &str,
) -> Result<bool, DbErr> {
    let found = email_suppressions::Entity::find()
        .filter(S::EmailHash.eq(email_hash(email)))
        .filter(
            Condition::any().add(S::OrganisationId.is_null()).add(
                Condition::all()
                    .add(S::OrganisationId.eq(organisation_id))
                    .add(S::ExpiresAt.gt(now())),
            ),
        )
        .one(db)
        .await?;
    Ok(found.is_some())
}

/// Whether a confirm mail to `email` may go out now: not suppressed, within the daily caps,
/// and not the third unconfirmed mail in 30 days (which suppresses the address as `ignored`
/// for this organisation).
/// Fails closed when Redis is unavailable.
async fn may_mail(
    db: &DatabaseConnection,
    redis: &redis::Client,
    organisation_id: Uuid,
    email: &str,
) -> Result<bool, ApiError> {
    if is_suppressed(db, organisation_id, email).await? {
        return Ok(false);
    }
    let hash = email_hash(email);
    let counted = async {
        let mut c = redis.get_multiplexed_async_connection().await?;
        let address = format!("ratelimit:recipient_confirm:email:{hash}");
        let org = format!("ratelimit:recipient_confirm:org:{organisation_id}");
        if !hit(&mut c, &address, MAILS_PER_ADDRESS, DAY_SECS).await?
            || !hit(&mut c, &org, MAILS_PER_ORG, DAY_SECS).await?
        {
            return Ok(Some(false));
        }
        let fresh = hit(
            &mut c,
            &unconfirmed_key(organisation_id, &hash),
            UNCONFIRMED_CAP,
            UNCONFIRMED_WINDOW_SECS,
        )
        .await?;
        Ok::<_, redis::RedisError>(if fresh { Some(true) } else { None })
    };
    match counted.await {
        Ok(Some(ok)) => Ok(ok),
        Ok(None) => {
            suppress_ignored(db, organisation_id, hash).await?;
            Ok(false)
        }
        Err(_) => {
            tracing::warn!(
                error_code = "redis_unavailable",
                "confirm mail limit unavailable, not sending"
            );
            Ok(false)
        }
    }
}

/// The HMAC key for unsubscribe tokens, derived from `SESSION_SECRET`.
fn unsubscribe_mac(secret: &str, id: Uuid) -> Hmac<Sha256> {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, secret.as_bytes())
        .expand(b"opsagent-unsubscribe", &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    let mut m = Hmac::<Sha256>::new_from_slice(&key).expect("hmac accepts any key");
    m.update(id.as_bytes());
    m
}

/// `<recipient id>.<base64url HMAC-SHA256(key, id)>`: stable for the row's lifetime, so every
/// mail carries the same working link.
pub fn unsubscribe_token(secret: &str, id: Uuid) -> String {
    let mac = unsubscribe_mac(secret, id).finalize().into_bytes();
    format!("{}.{}", id.simple(), B64.encode(mac))
}

/// The recipient id a token was issued for, if its HMAC verifies (constant-time compare).
fn verify_unsubscribe(secret: &str, token: &str) -> Option<Uuid> {
    let (id, mac) = token.split_once('.')?;
    let id = Uuid::try_parse(id).ok()?;
    let mac = B64.decode(mac).ok()?;
    unsubscribe_mac(secret, id).verify_slice(&mac).ok()?;
    Some(id)
}

/// The footer link for recipient `id`.
pub fn unsubscribe_url(web_base_url: &str, secret: &str, id: Uuid) -> String {
    format!(
        "{}/unsubscribe/{}",
        web_base_url.trim_end_matches('/'),
        unsubscribe_token(secret, id)
    )
}

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
    redis: &redis::Client,
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
        let to = Confirm {
            organisation_id,
            email: &email,
            token: &token,
        };
        send_confirm(db, redis, mailer, web_base_url, to).await?;
    }
    Ok(row)
}

struct Confirm<'a> {
    organisation_id: Uuid,
    email: &'a str,
    token: &'a str,
}

/// Mails the confirm link unless `may_mail` refuses (answered as if sent either way).
async fn send_confirm(
    db: &DatabaseConnection,
    redis: &redis::Client,
    mailer: &dyn Mailer,
    web_base_url: &str,
    c: Confirm<'_>,
) -> Result<(), ApiError> {
    if !may_mail(db, redis, c.organisation_id, c.email).await? {
        return Ok(());
    }
    let org = organisations::Entity::find_by_id(c.organisation_id)
        .one(db)
        .await?;
    let name = org.map(|o| o.name).unwrap_or_default();
    let link = format!("{web_base_url}/recipients/confirm?token={}", c.token);
    if mailer
        .send(mail::recipient_confirm(c.email, &name, &link))
        .await
        .is_err()
    {
        tracing::error!(error_code = "mail_failed", "recipient confirm mail failed");
    }
    Ok(())
}

/// Activates the pending recipient holding confirm `token`; 410 if unknown, used or expired.
pub async fn confirm(
    db: &DatabaseConnection,
    redis: &redis::Client,
    token: &str,
) -> Result<(), ApiError> {
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
    // A confirmed address is not ignoring us; best effort.
    if let Ok(mut c) = redis.get_multiplexed_async_connection().await {
        let _: redis::RedisResult<()> = redis::cmd("DEL")
            .arg(unconfirmed_key(
                row.organisation_id,
                &email_hash(&row.email),
            ))
            .query_async(&mut c)
            .await;
    }
    Ok(())
}

/// Unsubscribes the recipient a valid token names and suppresses its address everywhere.
/// Idempotent; 410 for a forged token or a deleted recipient.
pub async fn unsubscribe(
    db: &DatabaseConnection,
    secret: &str,
    token: &str,
) -> Result<(), ApiError> {
    let gone = || ApiError::gone("unsubscribe_token_invalid");
    let id = verify_unsubscribe(secret, token).ok_or_else(gone)?;
    // tenancy: the verified token names the recipient; the row names its organisation.
    let row = recipients::Entity::find_by_id(id)
        .one(db)
        .await?
        .ok_or_else(gone)?;
    let txn = db.begin().await?;
    let done = recipients::Entity::update_many()
        .col_expr(C::UnsubscribedAt, Some(now()).into())
        .col_expr(C::UpdatedAt, now().into())
        .filter(C::OrganisationId.eq(row.organisation_id))
        .filter(C::Id.eq(row.id))
        .filter(C::UnsubscribedAt.is_null())
        .exec(&txn)
        .await?;
    if done.rows_affected == 1 {
        audit::record_system(
            &txn,
            row.organisation_id,
            "recipient.unsubscribe",
            ("recipient", row.id.to_string()),
            "success",
            serde_json::json!({}),
        )
        .await?;
    }
    suppress_unsubscribed(&txn, email_hash(&row.email)).await?;
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
