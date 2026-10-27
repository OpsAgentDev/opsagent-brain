use std::{net::IpAddr, sync::Arc};

use opsagent_core::{repo::Clock, user::Email};

use super::ContactStore;
use crate::{
    actions::{hit_ip, RateLimiter, HOUR_SECS},
    error::AppResult,
    mailers::{
        contact::{contact_forward, ContactForward},
        Mailer,
    },
};

/// Messages per client IP (IPv6: per /64) per hour.
pub const PER_IP: i64 = 5;
/// Messages per hour across all clients.
pub const GLOBAL: i64 = 100;
pub const TOPICS: [&str; 5] = ["general", "sales", "support", "security", "partnership"];
const NAME_MAX: usize = 100;
const MESSAGE_MIN: usize = 10;
const MESSAGE_MAX: usize = 5000;

pub struct ContactInput {
    pub name: String,
    pub email: String,
    pub topic: String,
    pub message: String,
    /// Honeypot.
    pub website: Option<String>,
    pub client_ip: Option<IpAddr>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ContactOutcome {
    /// Saved, or dropped as a bot: indistinguishable to the caller.
    Accepted,
    Invalid,
    RateLimited,
}

pub struct SendContact {
    store: Arc<dyn ContactStore>,
    limiter: Arc<dyn RateLimiter>,
    mailer: Arc<dyn Mailer>,
    clock: Arc<dyn Clock>,
    contact_to: String,
}

impl SendContact {
    pub fn new(
        store: Arc<dyn ContactStore>,
        limiter: Arc<dyn RateLimiter>,
        mailer: Arc<dyn Mailer>,
        clock: Arc<dyn Clock>,
        contact_to: String,
    ) -> Self {
        Self {
            store,
            limiter,
            mailer,
            clock,
            contact_to,
        }
    }

    /// Both limits fail closed: refuse rather than forward unlimited mail.
    async fn within_limits(&self, ip: Option<IpAddr>) -> bool {
        let per_ip = hit_ip(&*self.limiter, "contact", ip, PER_IP, HOUR_SECS).await;
        let global = match per_ip {
            Ok(true) => self.limiter.hit("contact:global", GLOBAL, HOUR_SECS).await,
            other => other,
        };
        match global {
            Ok(ok) => ok,
            Err(e) => {
                tracing::warn!(error = %e, "contact rate limit unavailable, refusing");
                false
            }
        }
    }

    pub async fn run(&self, input: ContactInput) -> AppResult<ContactOutcome> {
        // Before any counter moves, so bots cannot use up the global cap.
        if input.website.as_deref().is_some_and(|w| !w.is_empty()) {
            return Ok(ContactOutcome::Accepted);
        }
        if !self.within_limits(input.client_ip).await {
            return Ok(ContactOutcome::RateLimited);
        }
        let name = input.name.trim();
        let message = input.message.trim();
        let (n, m) = (name.chars().count(), message.chars().count());
        let email = Email::parse(&input.email);
        let valid = (1..=NAME_MAX).contains(&n)
            && !name.chars().any(char::is_control)
            && (MESSAGE_MIN..=MESSAGE_MAX).contains(&m)
            && TOPICS.contains(&input.topic.as_str());
        let (true, Some(email)) = (valid, email) else {
            return Ok(ContactOutcome::Invalid);
        };
        let id = self
            .store
            .insert(name, &email, &input.topic, message)
            .await?;
        tracing::info!(message_id = %id, "contact message saved");
        // Off the request path; a send lost on shutdown leaves forwarded_at null.
        // Never log the name, address or text.
        let (store, mailer, clock, to) = (
            self.store.clone(),
            self.mailer.clone(),
            self.clock.clone(),
            self.contact_to.clone(),
        );
        let (name, email, topic, message) = (
            name.to_owned(),
            email.as_str().to_owned(),
            input.topic,
            message.to_owned(),
        );
        tokio::spawn(async move {
            let mail = contact_forward(
                &to,
                &ContactForward {
                    name: &name,
                    email: &email,
                    topic: &topic,
                    message: &message,
                },
            );
            if mailer.send(mail).await.is_err() {
                tracing::warn!(message_id = %id, "contact message not forwarded");
            } else if store.mark_forwarded(id, clock.now()).await.is_err() {
                tracing::warn!(message_id = %id, "contact forward not recorded");
            }
        });
        Ok(ContactOutcome::Accepted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{error::AppError, mailers::CaptureMailer};
    use async_trait::async_trait;
    use chrono::{DateTime, Utc};
    use opsagent_core::repo::SystemClock;
    use uuid::Uuid;

    /// Answers `global` for the global key and `Ok(true)` for the per-IP key; `panic_all`
    /// makes any call a failure.
    struct Limiter {
        global: AppResult<bool>,
        panic_all: bool,
        fail_ip: bool,
    }

    impl Limiter {
        fn new(global: AppResult<bool>) -> Self {
            Self {
                global,
                panic_all: false,
                fail_ip: false,
            }
        }
    }

    #[async_trait]
    impl RateLimiter for Limiter {
        async fn hit(&self, key: &str, _: i64, _: i64) -> AppResult<bool> {
            assert!(!self.panic_all, "limiter must not be touched");
            if self.fail_ip {
                return Err(AppError::Internal("redis down".into()));
            }
            if key == "contact:global" {
                return self
                    .global
                    .as_ref()
                    .map(|b| *b)
                    .map_err(|e| AppError::Internal(e.to_string()));
            }
            Ok(true)
        }
        async fn distinct(&self, _: &str, _: &str, _: i64) -> AppResult<i64> {
            unreachable!()
        }
        async fn clear(&self, _: &str) -> AppResult<()> {
            unreachable!()
        }
        async fn forget(&self, _: &str, _: &str) -> AppResult<()> {
            unreachable!()
        }
    }

    struct NoStore;

    #[async_trait]
    impl ContactStore for NoStore {
        async fn insert(&self, _: &str, _: &Email, _: &str, _: &str) -> AppResult<Uuid> {
            panic!("must not reach the store")
        }
        async fn mark_forwarded(&self, _: Uuid, _: DateTime<Utc>) -> AppResult<()> {
            unreachable!()
        }
    }

    fn action(limiter: Limiter, mail: Arc<CaptureMailer>) -> SendContact {
        SendContact::new(
            Arc::new(NoStore),
            Arc::new(limiter),
            mail,
            Arc::new(SystemClock),
            "info@opsagent.dev".into(),
        )
    }

    fn input() -> ContactInput {
        ContactInput {
            name: "Ann".into(),
            email: "a@b.io".into(),
            topic: "general".into(),
            message: "A message of enough length.".into(),
            website: None,
            client_ip: None,
        }
    }

    #[tokio::test]
    async fn honeypot_accepts_without_touching_limiter_or_store() {
        let mail = Arc::new(CaptureMailer::default());
        let mut l = Limiter::new(Ok(true));
        l.panic_all = true;
        let mut i = input();
        i.website = Some("http://spam".into());
        assert_eq!(
            action(l, mail.clone()).run(i).await.unwrap(),
            ContactOutcome::Accepted
        );
        assert!(mail.sent().is_empty());
    }

    #[tokio::test]
    async fn limiter_error_fails_closed() {
        let mut l = Limiter::new(Ok(true));
        l.fail_ip = true;
        let a = action(l, Arc::default());
        assert_eq!(a.run(input()).await.unwrap(), ContactOutcome::RateLimited);
    }

    #[tokio::test]
    async fn global_cap_refuses() {
        for g in [Ok(false), Err(AppError::Internal("redis down".into()))] {
            let a = action(Limiter::new(g), Arc::default());
            assert_eq!(a.run(input()).await.unwrap(), ContactOutcome::RateLimited);
        }
    }

    async fn rejected(mutate: impl FnOnce(&mut ContactInput)) {
        let mut i = input();
        mutate(&mut i);
        let a = action(Limiter::new(Ok(true)), Arc::default());
        assert_eq!(a.run(i).await.unwrap(), ContactOutcome::Invalid);
    }

    #[tokio::test]
    async fn rejects_bad_topic() {
        rejected(|i| i.topic = "billing".into()).await;
    }

    #[tokio::test]
    async fn rejects_short_message() {
        rejected(|i| i.message = "123456789".into()).await;
    }

    #[tokio::test]
    async fn rejects_long_name() {
        rejected(|i| i.name = "n".repeat(101)).await;
    }

    #[tokio::test]
    async fn rejects_control_chars_in_name() {
        rejected(|i| i.name = "Ann\nEvil".into()).await;
    }
}
