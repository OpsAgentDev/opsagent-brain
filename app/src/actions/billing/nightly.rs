//! The nightly `billing_sync` pass (billing.md, Build decisions 3, 8 and 17), per subscribed
//! organisation: connections still `revoked` when a period ended are disconnected, the trial
//! reminders go out on day 12 and day 14, and 7 days past due becomes `paused` with one
//! notice. Each mail is sent once: its ledger key sits on a `billing_notice` marker run keyed
//! by the organisation and the trial end (or period start), so later nights find it done.
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};

use chrono::{DateTime, Duration, Utc};
use opsagent_core::{
    audit::AuditEntry,
    billing::{BillingStatus as B, OrgBilling, SubscriptionState, Tier},
    connection::ConnectionStatus as S,
    run::{RunKey, RunStatus},
};
use opsagent_ledger::{effects::with_effect, LedgerError};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use super::BillingSync;
use crate::{
    actions::runs::classify::{lerr, LResult},
    mailers::Mail,
};

const TRIAL_DAYS: i64 = 14;
const PAUSE_AFTER_DAYS: i64 = 7;
/// The job type of the marker runs that hold the notices' ledger keys (no worker).
const NOTICE_JOB: &str = "billing_notice";
const REVOKED_REASON: &str = "revoked_at_period_end";

#[derive(Debug, Default, Serialize)]
struct Night {
    disconnected: u64,
    reminders: u64,
    paused: u64,
    notices: u64,
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
    pub(super) async fn nightly(&self, now: DateTime<Utc>) -> LResult<Value> {
        let orgs = self.uow.billing().subscribed_orgs().await.map_err(lerr)?;
        let mut night = Night::default();
        for org in orgs {
            if let Err(e) = self.night_org(org, now, &mut night).await {
                night.failed += 1;
                tracing::warn!(organisation_id = %org, error = %e, "billing nightly pass failed");
            }
        }
        tracing::info!(failed = night.failed, "billing nightly done");
        serde_json::to_value(night).map_err(lerr)
    }

    async fn night_org(&self, org: Uuid, now: DateTime<Utc>, night: &mut Night) -> LResult<()> {
        let repo = self.uow.billing();
        let b = repo.billing(org).await.map_err(lerr)?;
        let Some(sub) = b.subscription.as_ref() else {
            return Ok(());
        };
        night.disconnected += self.end_revoked(org, sub, now).await?;
        let day = sub.trial_ends_at.and_then(|t| reminder_day(t, now));
        if let (B::Trialing, Some(day)) = (b.status, day) {
            night.reminders += u64::from(self.trial_reminder(org, sub, day).await?);
        }
        let cutoff = now - Duration::days(PAUSE_AFTER_DAYS);
        let mut status = b.status;
        if status == B::PastDue && repo.pause(org, cutoff).await.map_err(lerr)? {
            status = B::Paused;
            night.paused += 1;
        }
        if status == B::Paused {
            night.notices += u64::from(self.paused_notice(org, &b, now).await?);
        }
        Ok(())
    }

    /// Disconnects connections revoked since before the current period began (a period ended
    /// while they were revoked), or once the stored period is over; returns how many.
    async fn end_revoked(
        &self,
        org: Uuid,
        sub: &SubscriptionState,
        now: DateTime<Utc>,
    ) -> LResult<u64> {
        let (start, end) = (sub.current_period_start, sub.current_period_end);
        let mut n = 0;
        for c in self.uow.connections().list(org).await.map_err(lerr)? {
            let since = c.verify_denied_first_at.unwrap_or(c.updated_at);
            let ended = start.is_some_and(|s| since < s) || end.is_some_and(|e| now >= e);
            if c.status != S::Revoked || !ended {
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
                n += 1;
            }
            tx.commit().await.map_err(lerr)?;
        }
        Ok(n)
    }

    async fn trial_reminder(&self, org: Uuid, sub: &SubscriptionState, day: i64) -> LResult<bool> {
        let Some(ends) = sub.trial_ends_at else {
            return Ok(false);
        };
        let price = sub.tier.unwrap_or(Tier::Team).monthly_usd();
        let date = ends.format("%-d %B %Y");
        let text = format!(
            "Your trial ends on {date}. You'll be charged ${price} × {} per month unless you \
             change plan or cancel.\n\nManage billing: {}",
            sub.quantity.max(1),
            self.billing_url(),
        );
        let subject = format!("Your OpsAgent trial ends on {date}");
        let key = format!("billing:trial_reminder:{day}");
        self.mail_owners(org, ends, &key, &subject, &text).await
    }

    async fn paused_notice(&self, org: Uuid, b: &OrgBilling, now: DateTime<Utc>) -> LResult<bool> {
        let sub = b.subscription.as_ref();
        let period = sub.and_then(|s| s.current_period_start);
        let period = period.or(b.past_due_since).unwrap_or(now);
        let text = format!(
            "Your OpsAgent payment has been overdue for {PAUSE_AFTER_DAYS} days, so scans and \
             deliveries are paused. Update your payment method to resume: {}",
            self.billing_url(),
        );
        let key = format!("billing:paused:{}", period.timestamp());
        let subject = "OpsAgent is paused: payment overdue";
        self.mail_owners(org, period, &key, subject, &text).await
    }

    fn billing_url(&self) -> String {
        let base = self.settings.web_base_url.trim_end_matches('/');
        format!("{base}/settings/billing")
    }

    /// The organisation's `billing_notice` marker run at `anchor` (created `done`, once).
    async fn marker(&self, org: Uuid, anchor: DateTime<Utc>) -> LResult<Uuid> {
        let key = RunKey {
            organisation_id: Some(org),
            connection_id: None,
            job_type: NOTICE_JOB.into(),
            scheduled_at: anchor,
        };
        let tx = self.uow.begin().await.map_err(lerr)?;
        let out = tx.ledger().create_run(key).await?;
        if out.created {
            let (id, fence) = (out.run.id, out.run.fence);
            tx.ledger()
                .set_status(id, fence, RunStatus::Done, None)
                .await?;
        }
        tx.commit().await.map_err(lerr)?;
        Ok(out.run.id)
    }

    /// Mails the owners once for ledger `key` on the marker at `anchor`; `true` when this call
    /// sent it. A failed send is retried the next night (Resend dedupes on the key).
    async fn mail_owners(
        &self,
        org: Uuid,
        anchor: DateTime<Utc>,
        key: &str,
        subject: &str,
        text: &str,
    ) -> LResult<bool> {
        let marker = self.marker(org, anchor).await?;
        let owners = self.uow.recipients().owners(org).await.map_err(lerr)?;
        let sent = AtomicBool::new(false);
        with_effect(self.uow.ledger(), marker, key, true, || async {
            for o in owners {
                let ok = self.guard.may_deliver(org, &o.email, o.member).await;
                if !ok.map_err(lerr)? {
                    continue;
                }
                let mail = Mail {
                    to: o.email,
                    subject: subject.into(),
                    text: text.into(),
                    idempotency_key: Some(format!("{marker}:{key}:{}", o.id)),
                    ..Default::default()
                };
                self.mailer.send(mail).await.map_err(|_| {
                    tracing::warn!(error_code = "mail_failed", "billing mail failed");
                    LedgerError::Job {
                        code: "mail_failed".into(),
                        retry: true,
                    }
                })?;
            }
            sent.store(true, SeqCst);
            Ok(None)
        })
        .await?;
        Ok(sent.load(SeqCst))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use chrono::TimeZone;
    use opsagent_core::billing::{
        BillingProvider, BillingRepo, BillingResult, CheckoutRequest, SubscriptionState,
    };
    use opsagent_ledger::redis;

    use super::*;
    use crate::{
        actions::{billing::BillingSettings, orgs::test_support::owned_org, recipients::MailGuard},
        adapters::memory::{FixedClock, MemRateLimiter, MemStore},
        mailers::CaptureMailer,
    };

    /// The nightly pass makes no Stripe calls.
    struct NoStripe;

    #[async_trait]
    impl BillingProvider for NoStripe {
        async fn create_customer(
            &self,
            _: Uuid,
            _: &str,
            _: &str,
            _: &str,
        ) -> BillingResult<String> {
            unreachable!()
        }
        async fn checkout_session(&self, _: &CheckoutRequest, _: &str) -> BillingResult<String> {
            unreachable!()
        }
        async fn portal_session(&self, _: &str, _: &str) -> BillingResult<String> {
            unreachable!()
        }
        async fn set_quantity(&self, _: &str, _: i32, _: bool, _: &str) -> BillingResult<()> {
            unreachable!()
        }
        async fn cancel_subscription(&self, _: &str, _: &str) -> BillingResult<()> {
            unreachable!()
        }
    }

    fn settings() -> BillingSettings {
        BillingSettings {
            stripe_configured: true,
            webhook_configured: true,
            webhook_secret: "whsec".into(),
            price_starter: "p_s".into(),
            price_team: "p_t".into(),
            price_scale: "p_x".into(),
            web_base_url: "https://opsagent.test/".into(),
            enforced: false,
        }
    }

    fn sync(store: &MemStore, mail: &Arc<CaptureMailer>, now: DateTime<Utc>) -> BillingSync {
        let uow = Arc::new(store.clone());
        let guard = Arc::new(MailGuard::new(
            uow.clone(),
            Arc::new(MemRateLimiter::default()),
        ));
        BillingSync::new(
            uow,
            redis::Client::open("redis://localhost:1").unwrap(),
            Arc::new(NoStripe),
            (mail.clone(), guard),
            Arc::new(FixedClock(now)),
            settings(),
        )
    }

    fn sub(status: B, ends: DateTime<Utc>) -> SubscriptionState {
        SubscriptionState {
            subscription_id: "sub_1".into(),
            status,
            tier: Some(Tier::Team),
            quantity: 1,
            trial_ends_at: Some(ends),
            current_period_start: Some(ends - Duration::days(14)),
            current_period_end: Some(ends),
        }
    }

    async fn night(store: &MemStore, mail: &Arc<CaptureMailer>, now: DateTime<Utc>) {
        let st = sync(store, mail, now).nightly(now).await.unwrap();
        assert_eq!(st["failed"], 0, "{st}");
    }

    #[test]
    fn reminder_days() {
        let ends = Utc.with_ymd_and_hms(2026, 11, 12, 10, 0, 0).unwrap();
        let at = |h: i64| reminder_day(ends, ends - Duration::hours(h));
        assert_eq!(at(3 * 24 + 1), None); // day 11
        assert_eq!(at(2 * 24 + 1), Some(12));
        assert_eq!(at(24 + 1), Some(12)); // day 13: a missed day-12 reminder still goes
        assert_eq!(at(1), Some(14));
        assert_eq!(at(0), None);
    }

    #[tokio::test]
    async fn trial_reminders_day_12_and_14_once() {
        let (store, mail) = (MemStore::default(), Arc::new(CaptureMailer::default()));
        let (_, org) = owned_org(&store, "o@example.com", "Acme").await;
        let ends = Utc.with_ymd_and_hms(2026, 11, 12, 10, 0, 0).unwrap();
        let s = sub(B::Trialing, ends);
        store
            .apply_subscription(org.id, &s, ends - Duration::days(14))
            .await
            .unwrap();
        let hours = |h: i64| ends - Duration::hours(h);
        let mut sent = vec![];
        for h in [3 * 24 + 6, 2 * 24 + 6, 2 * 24 + 5, 24 + 6, 6, 5] {
            night(&store, &mail, hours(h)).await;
            sent.push(mail.sent().len());
        }
        assert_eq!(sent, [0, 1, 1, 1, 2, 2]);
        let m = mail.sent();
        assert_eq!(m[0].to, "o@example.com");
        assert_eq!(
            m[0].text.lines().next().unwrap(),
            "Your trial ends on 12 November 2026. You'll be charged $299 × 1 per month unless \
             you change plan or cancel."
        );
        assert!(m[0]
            .text
            .ends_with("https://opsagent.test/settings/billing"));
        assert_ne!(m[0].idempotency_key, m[1].idempotency_key);
        // Converted: no more reminders for an active subscription.
        let active = sub(B::Active, ends);
        store
            .apply_subscription(org.id, &active, ends)
            .await
            .unwrap();
        night(&store, &mail, hours(1)).await;
        assert_eq!(mail.sent().len(), 2);
    }

    #[tokio::test]
    async fn past_due_7_days_pauses_and_notifies_once() {
        let (store, mail) = (MemStore::default(), Arc::new(CaptureMailer::default()));
        let (_, org) = owned_org(&store, "o@example.com", "Acme").await;
        let t0 = Utc.with_ymd_and_hms(2026, 11, 1, 0, 0, 0).unwrap();
        let s = sub(B::Active, t0 + Duration::days(20));
        store
            .apply_subscription(org.id, &s, t0 - Duration::days(1))
            .await
            .unwrap();
        assert!(store.apply_payment(org.id, B::PastDue, t0).await.unwrap());
        let status = || async { store.billing(org.id).await.unwrap().status };
        night(&store, &mail, t0 + Duration::days(6)).await;
        assert_eq!((status().await, mail.sent().len()), (B::PastDue, 0));
        night(&store, &mail, t0 + Duration::days(7)).await;
        assert_eq!((status().await, mail.sent().len()), (B::Paused, 1));
        assert!(mail.sent()[0].text.contains("paused"));
        night(&store, &mail, t0 + Duration::days(8)).await;
        assert_eq!((status().await, mail.sent().len()), (B::Paused, 1));
        // Paid: active again, and no notice.
        let paid = t0 + Duration::days(9);
        assert!(store.apply_payment(org.id, B::Active, paid).await.unwrap());
        night(&store, &mail, t0 + Duration::days(10)).await;
        assert_eq!((status().await, mail.sent().len()), (B::Active, 1));
    }
}
