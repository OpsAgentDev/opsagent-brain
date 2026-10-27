use std::{net::IpAddr, sync::Arc};

use opsagent_core::{repo::Clock, user::Email};

use super::WaitlistStore;
use crate::{
    actions::{hit_ip, RateLimiter, HOUR_SECS},
    error::AppResult,
    mailers::{waitlist::waitlist_confirmation, Mailer},
};

/// Joins per client IP (IPv6: per /64) per hour; duplicates count.
pub const PER_IP: i64 = 10;
/// Confirmation mails per hour across all clients; over it the row is kept, the mail skipped.
pub const GLOBAL_SENDS: i64 = 200;
/// Longest accepted `source`.
pub const SOURCE_MAX: usize = 64;

pub struct JoinInput {
    pub email: String,
    pub source: Option<String>,
    /// The client address as reported by the trusted proxy, when there is one.
    pub client_ip: Option<IpAddr>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum JoinOutcome {
    /// New or already on the list: indistinguishable to the caller.
    Accepted,
    Invalid,
    RateLimited,
}

pub struct JoinWaitlist {
    store: Arc<dyn WaitlistStore>,
    limiter: Arc<dyn RateLimiter>,
    mailer: Arc<dyn Mailer>,
    clock: Arc<dyn Clock>,
}

impl JoinWaitlist {
    pub fn new(
        store: Arc<dyn WaitlistStore>,
        limiter: Arc<dyn RateLimiter>,
        mailer: Arc<dyn Mailer>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            store,
            limiter,
            mailer,
            clock,
        }
    }

    pub async fn run(&self, input: JoinInput) -> AppResult<JoinOutcome> {
        match hit_ip(
            &*self.limiter,
            "waitlist",
            input.client_ip,
            PER_IP,
            HOUR_SECS,
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => return Ok(JoinOutcome::RateLimited),
            // Fail closed: refuse rather than accept unlimited sign-ups.
            Err(e) => {
                tracing::warn!(error = %e, "waitlist rate limit unavailable, refusing");
                return Ok(JoinOutcome::RateLimited);
            }
        }
        let Some(email) = Email::parse(&input.email) else {
            return Ok(JoinOutcome::Invalid);
        };
        if input
            .source
            .as_ref()
            .is_some_and(|s| s.chars().count() > SOURCE_MAX)
        {
            return Ok(JoinOutcome::Invalid);
        }
        if let Some(id) = self.store.insert(&email, input.source.as_deref()).await? {
            tracing::info!(entry_id = %id, "waitlist entry added");
            // Off the request path so latency does not reveal a fresh address from a duplicate.
            // A send lost on shutdown leaves confirmation_sent_at null, which is accepted.
            // Never log the address.
            let (store, limiter, mailer, clock) = (
                self.store.clone(),
                self.limiter.clone(),
                self.mailer.clone(),
                self.clock.clone(),
            );
            let to = email.as_str().to_owned();
            tokio::spawn(async move {
                match limiter
                    .hit("waitlist:global", GLOBAL_SENDS, HOUR_SECS)
                    .await
                {
                    Ok(true) => {}
                    _ => {
                        tracing::warn!(entry_id = %id, "waitlist confirmation skipped, global cap");
                        return;
                    }
                }
                if mailer.send(waitlist_confirmation(&to)).await.is_err() {
                    tracing::warn!(entry_id = %id, "waitlist confirmation not sent");
                } else if store.mark_confirmed(id, clock.now()).await.is_err() {
                    tracing::warn!(entry_id = %id, "waitlist confirmation not recorded");
                }
            });
        }
        Ok(JoinOutcome::Accepted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{error::AppError, mailers::CaptureMailer};
    use async_trait::async_trait;
    use opsagent_core::repo::SystemClock;

    struct BrokenLimiter;

    #[async_trait]
    impl RateLimiter for BrokenLimiter {
        async fn hit(&self, _: &str, _: i64, _: i64) -> AppResult<bool> {
            Err(AppError::Internal("redis down".into()))
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
    impl WaitlistStore for NoStore {
        async fn insert(&self, _: &Email, _: Option<&str>) -> AppResult<Option<uuid::Uuid>> {
            panic!("must not reach the store")
        }
        async fn mark_confirmed(
            &self,
            _: uuid::Uuid,
            _: chrono::DateTime<chrono::Utc>,
        ) -> AppResult<()> {
            unreachable!()
        }
    }

    /// Allows the per-IP hit, answers `global` for the global key.
    struct GlobalLimiter(AppResult<bool>);

    #[async_trait]
    impl RateLimiter for GlobalLimiter {
        async fn hit(&self, key: &str, _: i64, _: i64) -> AppResult<bool> {
            if key == "waitlist:global" {
                return self
                    .0
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

    #[derive(Default)]
    struct FlakyStore {
        marks: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl WaitlistStore for FlakyStore {
        async fn insert(&self, _: &Email, _: Option<&str>) -> AppResult<Option<uuid::Uuid>> {
            Ok(Some(uuid::Uuid::new_v4()))
        }
        async fn mark_confirmed(
            &self,
            _: uuid::Uuid,
            _: chrono::DateTime<chrono::Utc>,
        ) -> AppResult<()> {
            self.marks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(AppError::Internal("db down".into()))
        }
    }

    fn input() -> JoinInput {
        JoinInput {
            email: "a@b.io".into(),
            source: None,
            client_ip: None,
        }
    }

    async fn until(mut done: impl FnMut() -> bool) {
        for _ in 0..200 {
            if done() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("timed out");
    }

    #[tokio::test]
    async fn mark_confirmed_failure_still_accepts() {
        let (store, mail) = (
            Arc::new(FlakyStore::default()),
            Arc::new(CaptureMailer::default()),
        );
        let join = JoinWaitlist::new(
            store.clone(),
            Arc::new(GlobalLimiter(Ok(true))),
            mail.clone(),
            Arc::new(SystemClock),
        );
        assert_eq!(join.run(input()).await.unwrap(), JoinOutcome::Accepted);
        until(|| store.marks.load(std::sync::atomic::Ordering::SeqCst) == 1).await;
        assert_eq!(mail.sent().len(), 1);
    }

    #[tokio::test]
    async fn global_cap_or_limiter_error_skips_send() {
        for g in [Ok(false), Err(AppError::Internal("redis down".into()))] {
            let (store, mail) = (
                Arc::new(FlakyStore::default()),
                Arc::new(CaptureMailer::default()),
            );
            let join = JoinWaitlist::new(
                store.clone(),
                Arc::new(GlobalLimiter(g)),
                mail.clone(),
                Arc::new(SystemClock),
            );
            assert_eq!(join.run(input()).await.unwrap(), JoinOutcome::Accepted);
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            assert!(mail.sent().is_empty());
            assert_eq!(store.marks.load(std::sync::atomic::Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn limiter_error_fails_closed() {
        let mail = Arc::new(CaptureMailer::default());
        let join = JoinWaitlist::new(
            Arc::new(NoStore),
            Arc::new(BrokenLimiter),
            mail.clone(),
            Arc::new(SystemClock),
        );
        let input = JoinInput {
            email: "a@b.io".into(),
            source: None,
            client_ip: None,
        };
        assert_eq!(join.run(input).await.unwrap(), JoinOutcome::RateLimited);
        assert!(mail.sent().is_empty());
    }
}
