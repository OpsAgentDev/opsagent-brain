//! Who may receive mail, and every cap that bounds what one user can make the system send.
//! Two questions, answered separately:
//!
//! - `may_deliver(org, address, member)`: deliveries to a confirmed recipient. Blocked by a
//!   global `unsubscribed` row (not for members and owners, whose mail has no unsubscribe link)
//!   or an unexpired `ignored` row for that organisation.
//! - `may_send_confirm(org, address)`: confirm mails. Also blocked by an unexpired global
//!   `confirm_blocked` row, and capped per (organisation, address), per address and per
//!   organisation each day. Fails closed when the rate limiter is unavailable.
//!
//! `ignored` (90 days, per organisation) follows that organisation's unconfirmed mails.
//! `confirm_blocked` (90 days, global) follows unconfirmed mails from 5 distinct owning users;
//! it never stops deliveries. There is no total per-address cap: it would count mails that were
//! later confirmed and block a legitimate shared address everywhere.
//! One owning user gets at most 2 confirm mails per address in 30 days across all of their
//! organisations, so creating organisations buys nothing. The 30-day counters expire, and the
//! address holder's confirm clears them (`confirmed`).
use std::sync::Arc;

use opsagent_core::repo::RepoResult;
use opsagent_deliver::repo::Suppression;
use uuid::Uuid;

use super::tokens::email_hash;
use crate::{
    actions::{uow::UnitOfWork, RateLimiter, DAY_SECS},
    error::AppResult,
};

/// Confirm mails per (organisation, address) per day.
pub const MAILS_PER_ORG_ADDRESS: i64 = 3;
/// Confirm mails per address per day, across organisations.
pub const MAILS_PER_ADDRESS: i64 = 6;
/// Confirm mails per organisation per day.
pub const MAILS_PER_ORG: i64 = 20;
/// Organisations a user may create per day (each gets a DEK, and owners can send mail).
pub const ORGS_PER_USER_PER_DAY: i64 = 5;
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

fn unconfirmed_key(organisation_id: Uuid, hash: &str) -> String {
    format!("recipient_confirm:unconfirmed:{organisation_id}:{hash}")
}

fn per_owner_key(owner: Uuid, hash: &str) -> String {
    format!("recipient_confirm:unconfirmed_owner:{owner}:{hash}")
}

fn unconfirmed_owners_key(hash: &str) -> String {
    format!("recipient_confirm:unconfirmed_owners:{hash}")
}

/// The limiter's verdict on one confirm mail.
enum Verdict {
    Send,
    Capped,
    IgnoredByOrg,
    Blocked,
}

pub struct MailGuard {
    recipients: Arc<dyn UnitOfWork>,
    limiter: Arc<dyn RateLimiter>,
}

impl MailGuard {
    pub fn new(recipients: Arc<dyn UnitOfWork>, limiter: Arc<dyn RateLimiter>) -> Self {
        Self {
            recipients,
            limiter,
        }
    }

    /// The organisation's creating owner: its earliest owner membership.
    async fn owner_of(&self, organisation_id: Uuid) -> RepoResult<Uuid> {
        let owners = self.recipients.recipients().owners(organisation_id).await?;
        // An organisation always keeps an owner; the org id stands in if that ever breaks.
        Ok(owners.into_iter().next().map_or(organisation_id, |o| o.id))
    }

    /// Whether a live suppression row for one of `reasons` matches: global rows, or this
    /// organisation's.
    async fn suppressed(
        &self,
        organisation_id: Uuid,
        email: &str,
        reasons: &[Suppression],
    ) -> RepoResult<bool> {
        let repo = self.recipients.recipients();
        let live = repo.suppressed(organisation_id, &email_hash(email)).await?;
        Ok(live.iter().any(|k| reasons.contains(k)))
    }

    /// Whether a delivery (briefing, weekly, alert) from `organisation_id` may go to a confirmed
    /// recipient at `email`. `confirm_blocked` does not apply. A `member` (or owner) skips only
    /// `unsubscribed`: another organisation's footer must not silence their own organisation's
    /// mail.
    pub async fn may_deliver(
        &self,
        organisation_id: Uuid,
        email: &str,
        member: bool,
    ) -> AppResult<bool> {
        let reasons: &[Suppression] = if member {
            &[Suppression::Ignored]
        } else {
            &[Suppression::Unsubscribed, Suppression::Ignored]
        };
        Ok(!self.suppressed(organisation_id, email, reasons).await?)
    }

    async fn count(&self, organisation_id: Uuid, owner: Uuid, hash: &str) -> AppResult<Verdict> {
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
        let l = &self.limiter;
        for (key, cap) in caps {
            if !l.hit(&key, cap, DAY_SECS).await? {
                return Ok(Verdict::Capped);
            }
        }
        let unconfirmed = unconfirmed_key(organisation_id, hash);
        if !l.hit(&unconfirmed, UNCONFIRMED_CAP, WINDOW_30D).await? {
            return Ok(Verdict::IgnoredByOrg);
        }
        // Counted across every organisation of this owner; only the address holder's confirm
        // resets it.
        if !l
            .hit(&per_owner_key(owner, hash), PER_OWNER_CAP, WINDOW_30D)
            .await?
        {
            return Ok(Verdict::Capped);
        }
        let set = unconfirmed_owners_key(hash);
        let owners = l.distinct(&set, &owner.to_string(), WINDOW_30D).await?;
        Ok(if owners >= UNCONFIRMED_OWNERS_CAP {
            Verdict::Blocked
        } else {
            Verdict::Send
        })
    }

    /// Whether a confirm mail from `organisation_id` to `email` may go out now. A refusal for
    /// unconfirmed mails writes `ignored` (this organisation) or `confirm_blocked` (global).
    pub async fn may_send_confirm(&self, organisation_id: Uuid, email: &str) -> AppResult<bool> {
        let all = [
            Suppression::Unsubscribed,
            Suppression::Ignored,
            Suppression::ConfirmBlocked,
        ];
        if self.suppressed(organisation_id, email, &all).await? {
            return Ok(false);
        }
        let hash = email_hash(email);
        let owner = self.owner_of(organisation_id).await?;
        let repo = self.recipients.recipients();
        match self.count(organisation_id, owner, &hash).await {
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
    pub async fn confirmed(&self, organisation_id: Uuid, email: &str) -> AppResult<()> {
        let hash = email_hash(email);
        let owner = self.owner_of(organisation_id).await?;
        let l = &self.limiter;
        // Best effort: a counter left behind only expires with its window.
        let _ = l.clear(&unconfirmed_key(organisation_id, &hash)).await;
        let _ = l.clear(&per_owner_key(owner, &hash)).await;
        let _ = l
            .forget(&unconfirmed_owners_key(&hash), &owner.to_string())
            .await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use opsagent_core::org::Role;

    use super::*;
    use crate::{
        actions::{recipients::test_support::*, uow::Repos},
        adapters::memory::MemStore,
    };

    const TO: &str = "target@example.com";

    #[tokio::test]
    async fn confirm_blocked_after_five_distinct_owners_blocks_confirms_only() {
        let store = MemStore::default();
        let g = guard(&store);
        let mut orgs = vec![];
        for i in 0..UNCONFIRMED_OWNERS_CAP + 1 {
            let o = org(&store, &format!("Org {i}")).await;
            member(&store, o, &format!("owner{i}@example.com"), Role::Owner).await;
            orgs.push(o);
        }
        // Four owners' mails go out unconfirmed; the fifth owner's trips the block.
        for (i, o) in orgs.iter().take(5).enumerate() {
            assert_eq!(g.may_send_confirm(*o, TO).await.unwrap(), i < 4, "{i}");
        }
        let hash = email_hash(TO);
        let rows = store.recipients().suppressed(orgs[5], &hash).await.unwrap();
        assert_eq!(rows, [Suppression::ConfirmBlocked]);
        // Global: a sixth owner's first confirm mail is refused too.
        assert!(!g.may_send_confirm(orgs[5], TO).await.unwrap());
        // Deliveries to a confirmed recipient are not blocked, member or not.
        assert!(g.may_deliver(orgs[0], TO, false).await.unwrap());
        assert!(g.may_deliver(orgs[5], TO, true).await.unwrap());
    }

    #[tokio::test]
    async fn members_skip_only_unsubscribed() {
        let store = MemStore::default();
        let (g, o) = (guard(&store), org(&store, "Acme").await);
        let hash = email_hash(TO);
        let repo = store.recipients();
        repo.suppress(None, &hash, Suppression::Unsubscribed)
            .await
            .unwrap();
        assert!(!g.may_deliver(o, TO, false).await.unwrap());
        assert!(g.may_deliver(o, TO, true).await.unwrap());
        let other = org(&store, "Other").await;
        repo.suppress(Some(o), &email_hash("m@example.com"), Suppression::Ignored)
            .await
            .unwrap();
        assert!(!g.may_deliver(o, "m@example.com", true).await.unwrap());
        assert!(g.may_deliver(other, "m@example.com", true).await.unwrap());
    }
}
