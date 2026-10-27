use std::{net::IpAddr, sync::Arc};

use opsagent_core::user::Email;

use super::WaitlistStore;
use crate::{
    actions::{hit_ip, RateLimiter, HOUR_SECS},
    error::AppResult,
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
}

impl JoinWaitlist {
    pub fn new(store: Arc<dyn WaitlistStore>, limiter: Arc<dyn RateLimiter>) -> Self {
        Self { store, limiter }
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
        }
        Ok(JoinOutcome::Accepted)
    }
}
