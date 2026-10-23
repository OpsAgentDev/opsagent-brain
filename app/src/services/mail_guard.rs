//! Who may receive mail. Two questions, answered separately:
//!
//! - `may_deliver(org, address, member)`: deliveries to a confirmed recipient. Blocked by a
//!   global `unsubscribed` row (not for members and owners, whose mail has no unsubscribe link)
//!   or an unexpired `ignored` row for that organisation.
//! - `may_send_confirm(org, address)`: confirm mails. Also blocked by an unexpired global
//!   `confirm_blocked` row, and capped per (organisation, address), per address and per
//!   organisation each day. Fails closed when Redis is unavailable.
//!
//! `ignored` (90 days, per organisation) follows that organisation's unconfirmed mails.
//! `confirm_blocked` (90 days, global) follows unconfirmed mails from 5 distinct owning users;
//! it never stops deliveries. There is no total per-address cap: it would count mails that were
//! later confirmed and block a legitimate shared address everywhere.
//! One owning user gets at most 2 confirm mails per address in 30 days across all of their
//! organisations, so creating organisations buys nothing. The 30-day counters expire, and the
//! address holder's confirm clears them (`confirmed`).
use chrono::{Duration, Utc};
use opsagent_ledger::redis;
use sea_orm::{
    ColumnTrait, Condition, ConnectionTrait, DatabaseConnection, DbBackend, DbErr, EntityTrait,
    QueryFilter, QueryOrder, Statement,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    api_error::ApiError,
    models::{
        _entities::{
            email_suppressions::{self, Column as S},
            members,
        },
        members::OWNER,
        now,
    },
    services::rate_limit::{distinct, hit, DAY_SECS},
};

/// Confirm mails per (organisation, address) per day.
pub const MAILS_PER_ORG_ADDRESS: i64 = 3;
/// Confirm mails per address per day, across organisations.
pub const MAILS_PER_ADDRESS: i64 = 6;
/// Confirm mails per organisation per day.
pub const MAILS_PER_ORG: i64 = 20;
/// Unconfirmed confirm mails per (organisation, address) in 30 days before the address is
/// suppressed as `ignored` for that organisation.
pub const UNCONFIRMED_CAP: i64 = 2;
/// Unconfirmed confirm mails per (owning user, address) in 30 days, across all of that user's
/// organisations; beyond it the mail is withheld silently. A confirm resets it.
pub const PER_OWNER_CAP: i64 = 2;
/// Distinct owning users whose organisations sent unconfirmed confirm mails to one address in
/// 30 days at which confirm mails to it are blocked for everyone (`confirm_blocked`).
pub const UNCONFIRMED_OWNERS_CAP: i64 = 5;
const WINDOW_30D: i64 = 30 * DAY_SECS;
/// Days an `ignored` or `confirm_blocked` row lasts.
pub const IGNORED_DAYS: i64 = 90;

/// Hex SHA-256 of the lowercased address: the suppression key (no plaintext email stored).
pub fn email_hash(email: &str) -> String {
    format!("{:x}", Sha256::digest(email.to_lowercase()))
}

fn unconfirmed_key(organisation_id: Uuid, hash: &str) -> String {
    format!("recipient_confirm:unconfirmed:{organisation_id}:{hash}")
}

fn per_owner_key(owner: Uuid, hash: &str) -> String {
    format!("recipient_confirm:unconfirmed_owner:{owner}:{hash}")
}

fn unconfirmed_owners_key(hash: &str) -> String {
    format!("recipient_confirm:unconfirmed_owners:{hash}")
}

/// The organisation's creating owner: its earliest owner membership.
async fn owner_of(db: &impl ConnectionTrait, organisation_id: Uuid) -> Result<Uuid, DbErr> {
    let m = members::Entity::find()
        .filter(members::Column::OrganisationId.eq(organisation_id))
        .filter(members::Column::Role.eq(OWNER))
        .order_by_asc(members::Column::CreatedAt)
        .one(db)
        .await?;
    // An organisation always keeps an owner; the org id stands in if that ever breaks.
    Ok(m.map_or(organisation_id, |m| m.user_id))
}

/// Records the global `unsubscribed` row; it replaces a `confirm_blocked` row (no expiry).
pub async fn suppress_unsubscribed(db: &impl ConnectionTrait, hash: String) -> Result<(), DbErr> {
    let sql =
        "INSERT INTO email_suppressions (id, organisation_id, email_hash, reason, expires_at) \
               VALUES ($1, NULL, $2, 'unsubscribed', NULL) \
               ON CONFLICT (organisation_id, email_hash) \
               DO UPDATE SET reason = 'unsubscribed', expires_at = NULL";
    let values = [Uuid::new_v4().into(), hash.into()];
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        sql,
        values,
    ))
    .await
    .map(|_| ())
}

/// Records (or renews) a 90-day `ignored` row for `organisation_id`.
pub async fn suppress_ignored(
    db: &impl ConnectionTrait,
    organisation_id: Uuid,
    hash: String,
) -> Result<(), DbErr> {
    expiring(db, Some(organisation_id), hash, "ignored").await
}

/// Records (or renews) the global 90-day `confirm_blocked` row; never downgrades an unsubscribe.
pub async fn block_confirms(db: &impl ConnectionTrait, hash: String) -> Result<(), DbErr> {
    expiring(db, None, hash, "confirm_blocked").await
}

async fn expiring(
    db: &impl ConnectionTrait,
    organisation_id: Option<Uuid>,
    hash: String,
    reason: &str,
) -> Result<(), DbErr> {
    let sql =
        "INSERT INTO email_suppressions (id, organisation_id, email_hash, reason, expires_at) \
               VALUES ($1, $2, $3, $4, $5) \
               ON CONFLICT (organisation_id, email_hash) \
               DO UPDATE SET expires_at = EXCLUDED.expires_at \
               WHERE email_suppressions.reason = EXCLUDED.reason";
    let expires = Utc::now() + Duration::days(IGNORED_DAYS);
    let values = [
        Uuid::new_v4().into(),
        organisation_id.into(),
        hash.into(),
        reason.into(),
        expires.fixed_offset().into(),
    ];
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        sql,
        values,
    ))
    .await
    .map(|_| ())
}

/// Whether a live suppression row for one of `reasons` matches: global rows, or this
/// organisation's.
async fn suppressed(
    db: &impl ConnectionTrait,
    organisation_id: Uuid,
    email: &str,
    reasons: &[&str],
) -> Result<bool, DbErr> {
    let live = Condition::any()
        .add(S::ExpiresAt.is_null())
        .add(S::ExpiresAt.gt(now()));
    let found = email_suppressions::Entity::find()
        .filter(S::EmailHash.eq(email_hash(email)))
        .filter(
            Condition::any()
                .add(S::OrganisationId.is_null())
                .add(S::OrganisationId.eq(organisation_id)),
        )
        .filter(S::Reason.is_in(reasons.iter().copied()))
        .filter(live)
        .one(db)
        .await?;
    Ok(found.is_some())
}

/// Whether a delivery (briefing, weekly, alert) from `organisation_id` may go to a confirmed
/// recipient at `email`. `confirm_blocked` does not apply. A `member` (or owner) skips only
/// `unsubscribed`: another organisation's footer must not silence their own organisation's mail.
pub async fn may_deliver(
    db: &impl ConnectionTrait,
    organisation_id: Uuid,
    email: &str,
    member: bool,
) -> Result<bool, DbErr> {
    let reasons: &[&str] = if member {
        &["ignored"]
    } else {
        &["unsubscribed", "ignored"]
    };
    Ok(!suppressed(db, organisation_id, email, reasons).await?)
}

/// The Redis-side verdict on one confirm mail.
enum Verdict {
    Send,
    Capped,
    IgnoredByOrg,
    Blocked,
}

async fn count(
    redis: &redis::Client,
    organisation_id: Uuid,
    owner: Uuid,
    hash: &str,
) -> redis::RedisResult<Verdict> {
    let mut c = redis.get_multiplexed_async_connection().await?;
    let caps = [
        (
            format!("ratelimit:recipient_confirm:email:{organisation_id}:{hash}"),
            MAILS_PER_ORG_ADDRESS,
        ),
        (
            format!("ratelimit:recipient_confirm:email:{hash}"),
            MAILS_PER_ADDRESS,
        ),
        (
            format!("ratelimit:recipient_confirm:org:{organisation_id}"),
            MAILS_PER_ORG,
        ),
    ];
    for (key, cap) in caps {
        if !hit(&mut c, &key, cap, DAY_SECS).await? {
            return Ok(Verdict::Capped);
        }
    }
    if !hit(
        &mut c,
        &unconfirmed_key(organisation_id, hash),
        UNCONFIRMED_CAP,
        WINDOW_30D,
    )
    .await?
    {
        return Ok(Verdict::IgnoredByOrg);
    }
    // Counted across every organisation of this owner; only the address holder's confirm resets it.
    if !hit(
        &mut c,
        &per_owner_key(owner, hash),
        PER_OWNER_CAP,
        WINDOW_30D,
    )
    .await?
    {
        return Ok(Verdict::Capped);
    }
    let owners = distinct(
        &mut c,
        &unconfirmed_owners_key(hash),
        &owner.to_string(),
        WINDOW_30D,
    )
    .await?;
    Ok(if owners >= UNCONFIRMED_OWNERS_CAP {
        Verdict::Blocked
    } else {
        Verdict::Send
    })
}

/// Whether a confirm mail from `organisation_id` to `email` may go out now. A refusal for
/// unconfirmed mails writes `ignored` (this organisation) or `confirm_blocked` (global).
pub async fn may_send_confirm(
    db: &DatabaseConnection,
    redis: &redis::Client,
    organisation_id: Uuid,
    email: &str,
) -> Result<bool, ApiError> {
    if suppressed(
        db,
        organisation_id,
        email,
        &["unsubscribed", "ignored", "confirm_blocked"],
    )
    .await?
    {
        return Ok(false);
    }
    let hash = email_hash(email);
    let owner = owner_of(db, organisation_id).await?;
    match count(redis, organisation_id, owner, &hash).await {
        Ok(Verdict::Send) => Ok(true),
        Ok(Verdict::Capped) => Ok(false),
        Ok(Verdict::IgnoredByOrg) => {
            suppress_ignored(db, organisation_id, hash).await?;
            Ok(false)
        }
        Ok(Verdict::Blocked) => {
            block_confirms(db, hash).await?;
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

/// A confirmed address is not ignoring `organisation_id`: clear its unconfirmed counters
/// (best effort).
pub async fn confirmed(
    db: &impl ConnectionTrait,
    redis: &redis::Client,
    organisation_id: Uuid,
    email: &str,
) -> Result<(), DbErr> {
    let hash = email_hash(email);
    let owner = owner_of(db, organisation_id).await?;
    if let Ok(mut c) = redis.get_multiplexed_async_connection().await {
        let _: redis::RedisResult<()> = redis::pipe()
            .del(unconfirmed_key(organisation_id, &hash))
            .del(per_owner_key(owner, &hash))
            .srem(unconfirmed_owners_key(&hash), owner.to_string())
            .query_async(&mut c)
            .await;
    }
    Ok(())
}
