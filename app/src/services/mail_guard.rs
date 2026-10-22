//! Who may receive mail: suppressions and the confirm-mail limits.
//!
//! - An explicit unsubscribe is global and permanent.
//! - `ignored` (confirm mails not acted on) lasts 90 days: per organisation after its own
//!   unconfirmed mails, and globally once several organisations went unconfirmed, so many
//!   organisations together cannot mail-bomb one address.
//! - Confirm mails are capped per (organisation, address), per address and per organisation
//!   each day. Every check fails closed when Redis is unavailable.
use chrono::{Duration, Utc};
use opsagent_ledger::redis;
use sea_orm::{
    ColumnTrait, Condition, ConnectionTrait, DatabaseConnection, DbBackend, DbErr, EntityTrait,
    QueryFilter, Statement,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    api_error::ApiError,
    models::{
        _entities::email_suppressions::{self, Column as S},
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
/// Distinct organisations with an unconfirmed confirm mail to one address in 30 days at which
/// the address is suppressed as `ignored` for everyone.
pub const UNCONFIRMED_ORGS_CAP: i64 = 3;
const WINDOW_30D: i64 = 30 * DAY_SECS;
/// Days an `ignored` suppression lasts.
pub const IGNORED_DAYS: i64 = 90;

/// Hex SHA-256 of the lowercased address: the suppression key (no plaintext email stored).
pub fn email_hash(email: &str) -> String {
    format!("{:x}", Sha256::digest(email.to_lowercase()))
}

fn unconfirmed_key(organisation_id: Uuid, hash: &str) -> String {
    format!("recipient_confirm:unconfirmed:{organisation_id}:{hash}")
}

fn unconfirmed_orgs_key(hash: &str) -> String {
    format!("recipient_confirm:unconfirmed_orgs:{hash}")
}

/// Records the global `unsubscribed` row; it replaces a global `ignored` row (no expiry).
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

/// Records (or renews) a 90-day `ignored` row for `organisation_id`, or globally for `None`.
/// Never downgrades a global unsubscribe.
pub async fn suppress_ignored(
    db: &impl ConnectionTrait,
    organisation_id: Option<Uuid>,
    hash: String,
) -> Result<(), DbErr> {
    let sql =
        "INSERT INTO email_suppressions (id, organisation_id, email_hash, reason, expires_at) \
               VALUES ($1, $2, $3, 'ignored', $4) \
               ON CONFLICT (organisation_id, email_hash) \
               DO UPDATE SET expires_at = EXCLUDED.expires_at \
               WHERE email_suppressions.reason = 'ignored'";
    let expires = Utc::now() + Duration::days(IGNORED_DAYS);
    let values = [
        Uuid::new_v4().into(),
        organisation_id.into(),
        hash.into(),
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

/// Whether mail from `organisation_id` to `email` is suppressed: a global unsubscribe, an
/// unexpired global `ignored` row, or an unexpired `ignored` row for that organisation.
/// Every delivery mail checks this.
pub async fn is_suppressed(
    db: &impl ConnectionTrait,
    organisation_id: Uuid,
    email: &str,
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
        .filter(live)
        .one(db)
        .await?;
    Ok(found.is_some())
}

/// The Redis-side verdict on one confirm mail.
enum Verdict {
    Send,
    Capped,
    IgnoredByOrg,
    IgnoredByMany,
}

async fn count(
    redis: &redis::Client,
    organisation_id: Uuid,
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
    let orgs = distinct(
        &mut c,
        &unconfirmed_orgs_key(hash),
        &organisation_id.to_string(),
        WINDOW_30D,
    )
    .await?;
    Ok(if orgs >= UNCONFIRMED_ORGS_CAP {
        Verdict::IgnoredByMany
    } else {
        Verdict::Send
    })
}

/// Whether a confirm mail to `email` may go out now. Refusals that mean "ignored" write the
/// suppression (for this organisation, or globally).
pub async fn may_send_confirm(
    db: &DatabaseConnection,
    redis: &redis::Client,
    organisation_id: Uuid,
    email: &str,
) -> Result<bool, ApiError> {
    if is_suppressed(db, organisation_id, email).await? {
        return Ok(false);
    }
    let hash = email_hash(email);
    match count(redis, organisation_id, &hash).await {
        Ok(Verdict::Send) => Ok(true),
        Ok(Verdict::Capped) => Ok(false),
        Ok(Verdict::IgnoredByOrg) => {
            suppress_ignored(db, Some(organisation_id), hash).await?;
            Ok(false)
        }
        Ok(Verdict::IgnoredByMany) => {
            suppress_ignored(db, None, hash).await?;
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
pub async fn confirmed(redis: &redis::Client, organisation_id: Uuid, email: &str) {
    let hash = email_hash(email);
    if let Ok(mut c) = redis.get_multiplexed_async_connection().await {
        let _: redis::RedisResult<()> = redis::pipe()
            .del(unconfirmed_key(organisation_id, &hash))
            .srem(unconfirmed_orgs_key(&hash), organisation_id.to_string())
            .query_async(&mut c)
            .await;
    }
}
