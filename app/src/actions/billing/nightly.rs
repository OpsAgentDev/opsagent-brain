//! The nightly `billing_sync` pass (billing.md, Build decisions 3, 8 and 17), per subscribed
//! organisation: connections still `revoked` within `RENEWAL_WINDOW` of the period's end are
//! disconnected and the quantity is reconciled (so the renewal does not bill them), the trial
//! reminders go out on day 12 and day 14, a first failed payment and an ended trial each get
//! one notice, and 7 days past due becomes `paused` with one notice. The trial-started notice
//! is here too, sent by the organisation's own run. Each mail is sent once per owner: its ledger key (`<key>:<owner id>`) sits on a
//! `billing_notice` marker run keyed by the organisation and the trial end (or period start),
//! so later nights find it done.
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};

use chrono::{DateTime, Duration, Utc};
use opsagent_core::{
    audit::AuditEntry,
    billing::{
        BillingStatus as B, OrgBilling, SubscriptionState, Tier, PAUSE_AFTER_DAYS,
        REVOKED_AT_PERIOD_END as REVOKED_REASON,
    },
    connection::ConnectionStatus as S,
    org::org_web_base,
};
use opsagent_ledger::{effects::with_effect, LedgerError};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use super::{enqueue_sync, BillingSync};
use crate::{
    actions::day_counts::Counted,
    actions::runs::{
        classify::{lerr, LResult},
        notice_marker,
    },
    mailers::{branded, Mail},
};

const TRIAL_DAYS: i64 = 14;
/// A trial that ended longer ago than this gets no "trial ended" mail (no backlog on deploy).
const TRIAL_ENDED_NOTICE_DAYS: i64 = 3;
/// A revoked connection is disconnected once its period ends within this many hours: two
/// nightly runs, so one failed or missed night still lands before the renewal.
const RENEWAL_WINDOW_HOURS: i64 = 50;

#[derive(Debug, Default, Serialize)]
struct Night {
    disconnected: u64,
    reminders: u64,
    paused: u64,
    notices: u64,
    /// Trial-ended and payment-failed notices.
    lifecycle: u64,
    /// Organisations whose pass failed (logged; retried the next night).
    failed: u64,
}

/// The reminder due `now` for a trial ending at `ends`: day 12 (also on day 13, if missed),
/// or day 14 (its last day). Day = 14 - whole days left.
fn reminder_day(ends: DateTime<Utc>, now: DateTime<Utc>) -> Option<i64> {
    if ends <= now {
        return None;
    }
    match TRIAL_DAYS - (ends - now).num_days() {
        12 | 13 => Some(12),
        d if d >= TRIAL_DAYS => Some(TRIAL_DAYS),
        _ => None,
    }
}

impl BillingSync {
    /// Every subscribed organisation in turn; one failing is counted and does not stop the rest.
    pub(super) async fn nightly(&self, run_id: Uuid, now: DateTime<Utc>) -> LResult<Value> {
        let orgs = self.uow.billing().subscribed_orgs().await.map_err(lerr)?;
        let mut night = Night::default();
        for org in orgs {
            if let Err(e) = self.night_org(run_id, org, now, &mut night).await {
                night.failed += 1;
                tracing::warn!(organisation_id = %org, error = %e, "billing nightly pass failed");
            }
        }
        tracing::info!(failed = night.failed, "billing nightly done");
        let counter = &self.counter;
        counter.add(Counted::BillingOrg, night.failed).await;
        serde_json::to_value(night).map_err(lerr)
    }

    async fn night_org(
        &self,
        run_id: Uuid,
        org: Uuid,
        now: DateTime<Utc>,
        night: &mut Night,
    ) -> LResult<()> {
        let repo = self.uow.billing();
        let b = repo.billing(org).await.map_err(lerr)?;
        let Some(sub) = b.subscription.as_ref() else {
            return Ok(());
        };
        if b.status == B::TrialEnded {
            // Nothing to sync or pause: the subscription is over.
            night.lifecycle += u64::from(self.trial_ended_notice(org, sub, now).await?);
            return Ok(());
        }
        night.disconnected += self.end_revoked(org, sub, now).await?;
        if self.settings.stripe_configured {
            self.sync_quantity(run_id, org).await?;
        }
        let day = sub.trial_ends_at.and_then(|t| reminder_day(t, now));
        if let (B::Trialing, Some(day), false) = (b.status, day, sub.cancel_at_period_end) {
            night.reminders += u64::from(self.trial_reminder(org, sub, day, now).await?);
        }
        let cutoff = now - Duration::days(PAUSE_AFTER_DAYS);
        let mut status = b.status;
        if status == B::PastDue && repo.pause(org, cutoff).await.map_err(lerr)? {
            status = B::Paused;
            night.paused += 1;
        }
        if status == B::PastDue {
            night.lifecycle += u64::from(self.payment_failed_notice(org, &b).await?);
        }
        if status == B::Paused {
            night.notices += u64::from(self.paused_notice(org, &b, now).await?);
        }
        Ok(())
    }

    /// Disconnects connections still revoked once the stored period ends within
    /// `RENEWAL_WINDOW_HOURS`, each with an organisation `billing_sync` run (retried by the
    /// ledger if the nightly's own sync fails); returns how many.
    async fn end_revoked(
        &self,
        org: Uuid,
        sub: &SubscriptionState,
        now: DateTime<Utc>,
    ) -> LResult<u64> {
        let window = Duration::hours(RENEWAL_WINDOW_HOURS);
        if !sub.current_period_end.is_some_and(|e| now >= e - window) {
            return Ok(0);
        }
        let mut n = 0;
        for c in self.uow.connections().list(org).await.map_err(lerr)? {
            if c.status != S::Revoked {
                continue;
            }
            let tx = self.uow.begin().await.map_err(lerr)?;
            // Only from revoked: a role that came back since the list is left alone.
            let repo = tx.connections();
            let cas = repo.cas_status(org, c.id, S::Revoked, S::Disconnected, Some(REVOKED_REASON));
            if cas.await.map_err(lerr)? {
                let target = ("connection", c.id.to_string());
                let entry =
                    AuditEntry::system(org, "connection.disconnect", target, REVOKED_REASON);
                tx.audit().record(entry).await.map_err(lerr)?;
                enqueue_sync(&*tx, org, now).await.map_err(lerr)?;
                n += 1;
            }
            tx.commit().await.map_err(lerr)?;
        }
        Ok(n)
    }

    async fn trial_reminder(
        &self,
        org: Uuid,
        sub: &SubscriptionState,
        day: i64,
        now: DateTime<Utc>,
    ) -> LResult<bool> {
        let Some(ends) = sub.trial_ends_at else {
            return Ok(false);
        };
        let price = sub.tier.unwrap_or(Tier::Team).monthly_usd();
        let n = sub.quantity.max(1).unsigned_abs();
        let charge = if n == 1 {
            format!("${price} a month")
        } else {
            format!(
                "${price} a month for each of your {n} cloud accounts (${} in all)",
                price * n
            )
        };
        let date = ends.format("%-d %B %Y");
        let (subject, lead) = match (ends.date_naive() - now.date_naive()).num_days() {
            0 => (
                "Your OpsAgent trial ends today".to_owned(),
                format!("Your free trial ends today ({date}). This is the last reminder."),
            ),
            1 => (
                "Your OpsAgent trial ends tomorrow".to_owned(),
                format!("Your free trial ends tomorrow ({date}). This is the last reminder."),
            ),
            _ => (
                format!("Your OpsAgent trial ends on {date}"),
                format!("Your free trial ends on {date}."),
            ),
        };
        let billing_url = self.billing_url(org).await?;
        let text = format!(
            "{lead} After that you'll be charged {charge}, plus tax where applicable, unless you \
             change plan or cancel before then.\n\nManage billing: {}",
            billing_url,
        );
        let key = format!("billing:trial_reminder:{day}");
        self.mail_owners(org, ends, &key, &subject, &text, &billing_url)
            .await
    }

    /// One mail when a trial has just started (the webhook that starts it queues this
    /// organisation's run); not for a trial already under way (no backlog on deploy, and none
    /// from a later run of the organisation).
    pub(super) async fn trial_started_notice(
        &self,
        org: Uuid,
        now: DateTime<Utc>,
    ) -> LResult<bool> {
        let b = self.uow.billing().billing(org).await.map_err(lerr)?;
        let sub = b.subscription.as_ref().filter(|_| b.status == B::Trialing);
        let Some((sub, ends)) = sub.and_then(|s| Some((s, s.trial_ends_at?))) else {
            return Ok(false);
        };
        if ends - now < Duration::days(TRIAL_DAYS - 1) {
            return Ok(false);
        }
        let price = sub.tier.unwrap_or(Tier::Team).monthly_usd();
        let billing_url = self.billing_url(org).await?;
        let text = format!(
            "Your free trial runs until {}. On that day your card is charged US${price} a month \
             per connected cloud account, plus tax where applicable.\n\nCancel any time before \
             then in Settings > Billing and nothing is charged.\n\nThe trial covers one cloud \
             account.\n\nManage billing: {billing_url}",
            ends.format("%-d %B %Y"),
        );
        let subject = "Your OpsAgent trial has started";
        let key = "billing:trial_started";
        self.mail_owners(org, ends, key, subject, &text, &billing_url)
            .await
    }

    /// One mail when a trial has just ended (expired or cancelled); not for old ones.
    async fn trial_ended_notice(
        &self,
        org: Uuid,
        sub: &SubscriptionState,
        now: DateTime<Utc>,
    ) -> LResult<bool> {
        let Some(ends) = sub.trial_ends_at else {
            return Ok(false);
        };
        if now - ends > Duration::days(TRIAL_ENDED_NOTICE_DAYS) {
            return Ok(false);
        }
        let billing_url = self.billing_url(org).await?;
        let text = format!(
            "Your OpsAgent free trial has ended, so scans and deliveries have stopped. Choose a \
             plan to start them again: {}",
            billing_url,
        );
        let subject = "Your OpsAgent trial has ended";
        let key = "billing:trial_ended";
        self.mail_owners(org, ends, key, subject, &text, &billing_url)
            .await
    }

    /// One mail per failed-payment spell (keyed on its `past_due_since`); the paused notice
    /// follows if it is not fixed.
    async fn payment_failed_notice(&self, org: Uuid, b: &OrgBilling) -> LResult<bool> {
        let Some(since) = b.past_due_since else {
            return Ok(false);
        };
        let billing_url = self.billing_url(org).await?;
        let text = format!(
            "We could not take your latest OpsAgent payment. Update your payment method within \
             {PAUSE_AFTER_DAYS} days to keep scans and deliveries running: {}",
            billing_url,
        );
        let key = format!("billing:payment_failed:{}", since.timestamp());
        let subject = "Your OpsAgent payment failed";
        self.mail_owners(org, since, &key, subject, &text, &billing_url)
            .await
    }

    async fn paused_notice(&self, org: Uuid, b: &OrgBilling, now: DateTime<Utc>) -> LResult<bool> {
        let sub = b.subscription.as_ref();
        let period = sub.and_then(|s| s.current_period_start);
        let period = period.or(b.past_due_since).unwrap_or(now);
        let billing_url = self.billing_url(org).await?;
        let text = format!(
            "Your OpsAgent payment has been overdue for {PAUSE_AFTER_DAYS} days, so scans and \
             deliveries are paused. Update your payment method to resume: {}",
            billing_url,
        );
        let key = format!("billing:paused:{}", period.timestamp());
        let subject = "OpsAgent is paused: payment overdue";
        self.mail_owners(org, period, &key, subject, &text, &billing_url)
            .await
    }

    async fn billing_url(&self, org: Uuid) -> LResult<String> {
        let o = self.uow.orgs().get(org).await.map_err(lerr)?;
        let base = org_web_base(
            &self.settings.web_base_url,
            &o.ok_or(LedgerError::NotFound)?.slug,
        );
        Ok(format!("{base}/settings/billing"))
    }

    /// Mails each owner once for ledger key `<key>:<owner id>` on the marker at `anchor`, so a
    /// failure part-way never resends to owners already mailed; `true` when this call sent
    /// any. A failed send is retried the next night (Resend dedupes on the key).
    async fn mail_owners(
        &self,
        org: Uuid,
        anchor: DateTime<Utc>,
        key: &str,
        subject: &str,
        text: &str,
        link: &str,
    ) -> LResult<bool> {
        let marker = notice_marker(&*self.uow, Some(org), anchor).await?;
        let owners = self.uow.recipients().owners(org).await.map_err(lerr)?;
        let sent = AtomicBool::new(false);
        for o in owners {
            if !self
                .guard
                .may_deliver(org, &o.email, o.member)
                .await
                .map_err(lerr)?
            {
                continue;
            }
            let key = format!("{key}:{}", o.id);
            let mail = Mail {
                to: o.email,
                subject: subject.into(),
                html: Some(branded(subject, text, Some(("Manage billing", link)))),
                text: text.into(),
                idempotency_key: Some(format!("{marker}:{key}")),
                ..Default::default()
            };
            with_effect(self.uow.ledger(), marker, &key, true, || async {
                self.mailer.send(mail).await.map_err(|_| {
                    tracing::warn!(error_code = "mail_failed", "billing mail failed");
                    LedgerError::Job {
                        code: "mail_failed".into(),
                        retry: true,
                    }
                })?;
                sent.store(true, SeqCst);
                Ok(None)
            })
            .await?;
        }
        Ok(sent.load(SeqCst))
    }
}

#[cfg(test)]
pub(super) mod tests;
