//! `task waitlist:announce`: one mail to each waitlist entry once sign-ups are open.
use std::{sync::Arc, time::Duration};

use opsagent_core::{repo::Clock, user::SignupAllowlist};

use super::AnnounceStore;
use crate::{
    error::{AppError, AppResult},
    mailers::{waitlist::signups_open, Mailer},
};

/// The gap between sends: Resend allows 2 requests a second per account and does not retry
/// a 429 here, so one a second leaves room for sign-in mail sent meanwhile.
pub const SEND_GAP: Duration = Duration::from_secs(1);

#[derive(Debug, PartialEq, Eq)]
pub struct AnnounceReport {
    pub sent: u64,
    /// Not sent this time; still unannounced, so a re-run tries them again.
    pub failed: u64,
}

pub struct AnnounceWaitlist {
    store: Arc<dyn AnnounceStore>,
    mailer: Arc<dyn Mailer>,
    clock: Arc<dyn Clock>,
    signup: SignupAllowlist,
    web_base_url: String,
    gap: Duration,
}

impl AnnounceWaitlist {
    pub fn new(
        store: Arc<dyn AnnounceStore>,
        mailer: Arc<dyn Mailer>,
        clock: Arc<dyn Clock>,
        signup: SignupAllowlist,
        web_base_url: String,
        gap: Duration,
    ) -> Self {
        Self {
            store,
            mailer,
            clock,
            signup,
            web_base_url,
            gap,
        }
    }

    /// Mails every unannounced entry, one at a time. Safe to re-run: an entry is marked
    /// once its mail went, and the Idempotency-Key covers a crash between the two.
    pub async fn run(&self) -> AppResult<AnnounceReport> {
        if !self.signup.is_wildcard() {
            return Err(AppError::Invalid(
                "sign-ups are not open: SIGNUP_ALLOWED_DOMAINS must be `*`".into(),
            ));
        }
        let mut report = AnnounceReport { sent: 0, failed: 0 };
        for (id, email) in self.store.unannounced().await? {
            // Never log the address.
            let key = format!("waitlist:announce:{id}");
            match self
                .mailer
                .send(signups_open(&email, &self.web_base_url, key))
                .await
            {
                Ok(()) => {
                    self.store.mark_announced(id, self.clock.now()).await?;
                    report.sent += 1;
                }
                Err(_) => {
                    tracing::warn!(entry_id = %id, "waitlist announcement not sent");
                    report.failed += 1;
                }
            }
            tokio::time::sleep(self.gap).await;
        }
        tracing::info!(
            sent = report.sent,
            failed = report.failed,
            "waitlist announced"
        );
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use chrono::{DateTime, Utc};
    use opsagent_core::repo::SystemClock;
    use uuid::Uuid;

    use super::*;
    use crate::mailers::{CaptureMailer, Mail};

    #[derive(Default)]
    struct Store(Mutex<Vec<(Uuid, String, bool)>>);

    impl Store {
        fn with(emails: &[&str]) -> Arc<Self> {
            let rows = emails
                .iter()
                .map(|e| (Uuid::new_v4(), (*e).to_owned(), false))
                .collect();
            Arc::new(Self(Mutex::new(rows)))
        }
    }

    #[async_trait]
    impl AnnounceStore for Store {
        async fn unannounced(&self) -> AppResult<Vec<(Uuid, String)>> {
            let rows = self.0.lock().unwrap();
            let open = rows.iter().filter(|r| !r.2);
            Ok(open.map(|r| (r.0, r.1.clone())).collect())
        }

        async fn mark_announced(&self, id: Uuid, _: DateTime<Utc>) -> AppResult<()> {
            let mut rows = self.0.lock().unwrap();
            rows.iter_mut().find(|r| r.0 == id).unwrap().2 = true;
            Ok(())
        }
    }

    fn announce(store: &Arc<Store>, mailer: Arc<dyn Mailer>, signup: &str) -> AnnounceWaitlist {
        AnnounceWaitlist::new(
            store.clone(),
            mailer,
            Arc::new(SystemClock),
            SignupAllowlist::parse(signup),
            "https://opsagent.dev/".into(),
            Duration::ZERO,
        )
    }

    #[tokio::test]
    async fn mails_each_entry_once_across_reruns() {
        let (store, mail) = (
            Store::with(&["a@b.io", "c@d.io"]),
            Arc::new(CaptureMailer::default()),
        );
        let a = announce(&store, mail.clone(), "*");
        assert_eq!(
            a.run().await.unwrap(),
            AnnounceReport { sent: 2, failed: 0 }
        );
        assert_eq!(
            a.run().await.unwrap(),
            AnnounceReport { sent: 0, failed: 0 }
        );
        let sent = mail.sent();
        assert_eq!(sent.len(), 2);
        assert!(sent[0].text.contains("https://opsagent.dev/sign-up"));
    }

    #[tokio::test]
    async fn refuses_unless_signups_are_open_with_a_wildcard() {
        for signup in ["opsagent.dev", ""] {
            let (store, mail) = (Store::with(&["a@b.io"]), Arc::new(CaptureMailer::default()));
            let err = announce(&store, mail.clone(), signup)
                .run()
                .await
                .unwrap_err();
            assert!(matches!(err, AppError::Invalid(_)), "{signup}: {err}");
            assert!(mail.sent().is_empty());
        }
    }

    /// Fails the first address, sends the rest.
    struct FailFirst(CaptureMailer, Mutex<bool>);

    #[async_trait]
    impl Mailer for FailFirst {
        async fn send(&self, m: Mail) -> Result<(), String> {
            let fail = !std::mem::replace(&mut *self.1.lock().unwrap(), true);
            if fail {
                return Err("boom".into());
            }
            self.0.send(m).await
        }
    }

    #[tokio::test]
    async fn failed_send_stays_unannounced_and_is_retried() {
        let store = Store::with(&["a@b.io", "c@d.io"]);
        let mailer = Arc::new(FailFirst(CaptureMailer::default(), Mutex::new(false)));
        let a = announce(&store, mailer.clone(), "*");
        assert_eq!(
            a.run().await.unwrap(),
            AnnounceReport { sent: 1, failed: 1 }
        );
        assert_eq!(
            a.run().await.unwrap(),
            AnnounceReport { sent: 1, failed: 0 }
        );
        assert_eq!(mailer.0.sent().len(), 2);
    }
}
