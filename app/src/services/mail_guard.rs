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
use opsagent_core::repo::RepoResult;
use opsagent_deliver::repo::{RecipientsRepo, Suppression};
use opsagent_ledger::redis;
use sea_orm::{ConnectionTrait, DatabaseConnection};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    actions::{RateLimiter, DAY_SECS},
    adapters::db::Pg,
    api_error::ApiError,
    error::AppResult,
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
async fn owner_of(repo: &dyn RecipientsRepo, organisation_id: Uuid) -> RepoResult<Uuid> {
    let first = repo.owners(organisation_id).await?.into_iter().next();
    // An organisation always keeps an owner; the org id stands in if that ever breaks.
    Ok(first.map_or(organisation_id, |o| o.id))
}

/// Whether a live suppression row for one of `reasons` matches: global rows, or this
/// organisation's.
async fn suppressed(
    repo: &dyn RecipientsRepo,
    organisation_id: Uuid,
    email: &str,
    reasons: &[Suppression],
) -> RepoResult<bool> {
    let live = repo.suppressed(organisation_id, &email_hash(email)).await?;
    Ok(live.iter().any(|k| reasons.contains(k)))
}

/// Whether a delivery (briefing, weekly, alert) from `organisation_id` may go to a confirmed
/// recipient at `email`. `confirm_blocked` does not apply. A `member` (or owner) skips only
/// `unsubscribed`: another organisation's footer must not silence their own organisation's mail.
pub async fn may_deliver(
    db: &impl ConnectionTrait,
    organisation_id: Uuid,
    email: &str,
    member: bool,
) -> RepoResult<bool> {
    let reasons: &[Suppression] = if member {
        &[Suppression::Ignored]
    } else {
        &[Suppression::Unsubscribed, Suppression::Ignored]
    };
    Ok(!suppressed(&Pg::new(db), organisation_id, email, reasons).await?)
}

/// The Redis-side verdict on one confirm mail.
enum Verdict {
    Send,
    Capped,
    IgnoredByOrg,
    Blocked,
}

async fn count(
    limiter: &dyn RateLimiter,
    organisation_id: Uuid,
    owner: Uuid,
    hash: &str,
) -> AppResult<Verdict> {
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
        if !limiter.hit(&key, cap, DAY_SECS).await? {
            return Ok(Verdict::Capped);
        }
    }
    if !limiter
        .hit(
            &unconfirmed_key(organisation_id, hash),
            UNCONFIRMED_CAP,
            WINDOW_30D,
        )
        .await?
    {
        return Ok(Verdict::IgnoredByOrg);
    }
    // Counted across every organisation of this owner; only the address holder's confirm resets it.
    if !limiter
        .hit(&per_owner_key(owner, hash), PER_OWNER_CAP, WINDOW_30D)
        .await?
    {
        return Ok(Verdict::Capped);
    }
    let owners = limiter
        .distinct(
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
    limiter: &dyn RateLimiter,
    organisation_id: Uuid,
    email: &str,
) -> Result<bool, ApiError> {
    let repo = Pg::new(db);
    let all = [
        Suppression::Unsubscribed,
        Suppression::Ignored,
        Suppression::ConfirmBlocked,
    ];
    if suppressed(&repo, organisation_id, email, &all).await? {
        return Ok(false);
    }
    let hash = email_hash(email);
    let owner = owner_of(&repo, organisation_id).await?;
    match count(limiter, organisation_id, owner, &hash).await {
        Ok(Verdict::Send) => Ok(true),
        Ok(Verdict::Capped) => Ok(false),
        Ok(Verdict::IgnoredByOrg) => {
            let ignored = Suppression::Ignored;
            repo.suppress(Some(organisation_id), &hash, ignored).await?;
            Ok(false)
        }
        Ok(Verdict::Blocked) => {
            // Never downgrades an unsubscribe.
            repo.suppress(None, &hash, Suppression::ConfirmBlocked)
                .await?;
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
) -> RepoResult<()> {
    let hash = email_hash(email);
    let owner = owner_of(&Pg::new(db), organisation_id).await?;
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
