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
            // Inline, only for a fresh row: a duplicate or a lost race sends nothing.
            // Never log the address.
            match self
                .mailer
                .send(waitlist_confirmation(email.as_str()))
                .await
            {
                Ok(()) => self.store.mark_confirmed(id, self.clock.now()).await?,
                Err(_) => tracing::warn!(entry_id = %id, "waitlist confirmation not sent"),
            }
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
