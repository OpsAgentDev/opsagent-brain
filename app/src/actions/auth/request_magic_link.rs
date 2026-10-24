//! Magic-link requests, capped per address and per client IP. The caller always answers 202,
//! so a capped request looks exactly like a sent one (no enumeration).
use std::{
    net::{IpAddr, Ipv6Addr},
    sync::Arc,
};

use chrono::Duration;
use opsagent_core::{repo::Clock, user::Email};
use sha2::{Digest, Sha256};

use crate::{
    actions::{uow::UnitOfWork, RateLimiter, HOUR_SECS},
    error::AppResult,
    mailers::{magic_link as mail, Mailer},
    tokens::{hash_token, new_token},
};

/// Links per address per hour.
pub const PER_EMAIL: i64 = 5;
/// Requests per client IP (IPv6: per /64) per hour.
pub const PER_IP: i64 = 30;

pub struct MagicLinkInput {
    pub email: String,
    /// The client address as reported by the trusted proxy, when there is one.
    pub client_ip: Option<IpAddr>,
}

pub struct RequestMagicLink {
    users: Arc<dyn UnitOfWork>,
    limiter: Arc<dyn RateLimiter>,
    mailer: Arc<dyn Mailer>,
    web_base_url: String,
    clock: Arc<dyn Clock>,
}

/// The IP cap's bucket: an IPv6 client owns at least a /64, so the /64 is one client.
fn ip_bucket(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (u128::MAX << 64))),
        v4 => v4,
    }
}

impl RequestMagicLink {
    pub fn new(
        users: Arc<dyn UnitOfWork>,
        limiter: Arc<dyn RateLimiter>,
        mailer: Arc<dyn Mailer>,
        web_base_url: String,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            users,
            limiter,
            mailer,
            web_base_url,
            clock,
        }
    }

    /// Counts this request against the IP (when known), then against the normalised address.
    /// `false` once either hour's cap is passed.
    async fn under_cap(&self, email: &Email, ip: Option<IpAddr>) -> AppResult<bool> {
        if let Some(ip) = ip {
            let key = format!("ratelimit:magic_link:ip:{}", ip_bucket(ip));
            if !self.limiter.hit(&key, PER_IP, HOUR_SECS).await? {
                return Ok(false);
            }
        }
        let key = format!(
            "ratelimit:magic_link:email:{:x}",
            Sha256::digest(email.as_str())
        );
        self.limiter.hit(&key, PER_EMAIL, HOUR_SECS).await
    }

    /// Sends a sign-in link unless the address is invalid or either cap is passed.
    pub async fn run(&self, input: MagicLinkInput) -> AppResult<()> {
        let Some(email) = Email::parse(&input.email) else {
            return Ok(());
        };
        match self.under_cap(&email, input.client_ip).await {
            Ok(true) => {}
            Ok(false) => return Ok(()),
            // Fail closed: no mail rather than an unlimited one.
            Err(e) => {
                tracing::warn!(error = %e, "magic link rate limit unavailable, not sending");
                return Ok(());
            }
        }
        let users = self.users.users();
        let user = users.find_or_create_by_email(&email).await?;
        let token = new_token();
        let expires = self.clock.now() + Duration::minutes(15);
        users
            .issue_magic_link(user.id, &email, &hash_token(&token), expires)
            .await?;
        // The web page POSTs the token to `/auth/magic-link/redeem` after a click (login-CSRF safe).
        let link = format!(
            "{}/auth/callback?token={token}",
            self.web_base_url.trim_end_matches('/')
        );
        if let Err(e) = self
            .mailer
            .send(mail::magic_link(email.as_str(), &link))
            .await
        {
            tracing::error!(error = %e, "magic link mail failed");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use opsagent_core::user::Email;

    use super::*;
    use crate::{
        actions::{auth::test_support::*, uow::Repos},
        adapters::memory::MemStore,
        mailers::CaptureMailer,
    };

    fn input(email: &str) -> MagicLinkInput {
        MagicLinkInput {
            email: email.into(),
            client_ip: None,
        }
    }

    #[test]
    fn ipv6_buckets_by_64_and_ipv4_as_is() {
        let b = |s: &str| ip_bucket(s.parse().unwrap()).to_string();
        assert_eq!(b("2001:db8:1:2:3:4:5:6"), "2001:db8:1:2::");
        assert_eq!(b("2001:db8:1:2:ffff::1"), "2001:db8:1:2::");
        assert_eq!(b("203.0.113.7"), "203.0.113.7");
        // IPv4-mapped IPv6 is the IPv4 client, not the shared `::` bucket.
        assert_eq!(b("::ffff:203.0.113.7"), "203.0.113.7");
    }

    #[tokio::test]
    async fn request_link_for_unknown_email_creates_user_and_mails_once() {
        let (store, mail) = (MemStore::default(), Arc::new(CaptureMailer::default()));
        request_link(&store, &mail)
            .run(input("New@Example.com"))
            .await
            .unwrap();
        let sent = mail.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].to, "new@example.com");
        assert!(last_token(&mail).len() > 20);
        let email = Email::parse("new@example.com").unwrap();
        assert!(store.users().find_by_email(&email).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn request_link_over_cap_sends_nothing_but_succeeds() {
        let (store, mail) = (MemStore::default(), Arc::new(CaptureMailer::default()));
        let action = request_link(&store, &mail);
        for _ in 0..PER_EMAIL + 2 {
            action.run(input("cap@example.com")).await.unwrap();
        }
        assert_eq!(mail.sent().len(), PER_EMAIL as usize);
        // An invalid address is also a quiet success.
        action.run(input("not-an-email")).await.unwrap();
        assert_eq!(mail.sent().len(), PER_EMAIL as usize);
    }
}
