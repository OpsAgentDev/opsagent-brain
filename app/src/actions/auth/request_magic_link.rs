//! Magic-link requests, capped per address and per client IP. The caller always answers 202,
//! so a capped request looks exactly like a sent one (no enumeration).
use std::{net::IpAddr, sync::Arc};

use chrono::Duration;
use opsagent_core::{
    oauth::rules::consent_return_to,
    repo::Clock,
    user::{Email, NewMagicLink, PersonName, SignupAllowlist},
};
use sha2::{Digest, Sha256};

use crate::{
    actions::{ip_bucket, uow::UnitOfWork, RateLimiter, HOUR_SECS},
    error::AppResult,
    mailers::{magic_link as mail, Mailer},
    tokens::{code_hash, hash_token, new_code, new_token},
};

/// Links per address per hour.
pub const PER_EMAIL: i64 = 5;
/// Requests per client IP (IPv6: per /64) per hour.
pub const PER_IP: i64 = 30;

pub struct MagicLinkInput {
    pub email: String,
    /// The client address as reported by the trusted proxy, when there is one.
    pub client_ip: Option<IpAddr>,
    /// A requested post-sign-in destination; kept only if `consent_return_to` accepts it.
    pub return_to: Option<String>,
    /// A sign-up name; unusable values are ignored.
    pub name: Option<String>,
}

pub struct RequestMagicLink {
    users: Arc<dyn UnitOfWork>,
    limiter: Arc<dyn RateLimiter>,
    /// Sign-in mails per hour across all clients (`MAGIC_LINK_HOURLY_CAP`).
    hourly_cap: i64,
    mailer: Arc<dyn Mailer>,
    web_base_url: String,
    clock: Arc<dyn Clock>,
    /// Keys the stored code hashes (`SESSION_SECRET`).
    secret: String,
    signup: SignupAllowlist,
}

impl RequestMagicLink {
    pub fn new(
        users: Arc<dyn UnitOfWork>,
        (limiter, hourly_cap): (Arc<dyn RateLimiter>, i64),
        mailer: Arc<dyn Mailer>,
        web_base_url: String,
        clock: Arc<dyn Clock>,
        secret: String,
        signup: SignupAllowlist,
    ) -> Self {
        Self {
            users,
            limiter,
            hourly_cap,
            mailer,
            web_base_url,
            clock,
            secret,
            signup,
        }
    }

    /// Counts this request against the IP (when known), the normalised address, then the
    /// global hourly cap, in that order so requests the per-client caps refuse do not use up
    /// everyone's budget. `false` once any hour's cap is passed.
    async fn under_cap(&self, email: &Email, ip: Option<IpAddr>) -> AppResult<bool> {
        if let Some(ip) = ip {
            let key = format!("ratelimit:magic_link:ip:{}", ip_bucket(ip));
            if !self.limiter.hit(&key, PER_IP, HOUR_SECS).await? {
                return Ok(false);
            }
        }
        let key = format!(
            "ratelimit:magic_link:email:{}",
            crate::tokens::hex(Sha256::digest(email.as_str()))
        );
        if !self.limiter.hit(&key, PER_EMAIL, HOUR_SECS).await? {
            return Ok(false);
        }
        let global = "ratelimit:magic_link:global";
        let under = self.limiter.hit(global, self.hourly_cap, HOUR_SECS).await?;
        if !under {
            tracing::error!(
                error_code = "magic_link_global_cap",
                "magic link hourly cap reached, not sending"
            );
        }
        Ok(under)
    }

    /// Sends a sign-in link unless the address is invalid or a cap is passed.
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
        if !self.signup.allows(&email) && users.find_by_email(&email).await?.is_none() {
            let mail = mail::signup_closed(email.as_str(), &self.web_base_url);
            if let Err(e) = self.mailer.send(mail).await {
                tracing::error!(error = %e, "signup closed mail failed");
            }
            return Ok(());
        }
        let user = users.find_or_create_by_email(&email).await?;
        // Unproven until redeemed, so it rides on the link instead of being saved now.
        let name = input.name.as_deref().and_then(PersonName::parse);
        let return_to = input.return_to.as_deref().and_then(consent_return_to);
        let token = new_token();
        let token_hash = hash_token(&token);
        let code = new_code();
        let expires = self.clock.now() + Duration::minutes(15);
        users
            .issue_magic_link(NewMagicLink {
                user_id: user.id,
                email: &email,
                token_hash: &token_hash,
                code_hash: &code_hash(&self.secret, &token_hash, &code),
                return_to: return_to.as_deref(),
                name: name.as_ref(),
                expires_at: expires,
            })
            .await?;
        // The web page POSTs the token to `/auth/magic-link/redeem` after a click (login-CSRF safe).
        let link = format!(
            "{}/auth/callback?token={token}",
            self.web_base_url.trim_end_matches('/')
        );
        if let Err(e) = self
            .mailer
            .send(mail::magic_link(email.as_str(), &link, &code))
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
            return_to: None,
            name: None,
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
        let m = &sent[0];
        assert!(
            m.subject.starts_with("Your OpsAgent sign-in code: "),
            "{}",
            m.subject
        );
        let code = last_code(&mail);
        assert!(code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()));
        assert!(m.text.contains(&format!("Or enter this code: {code}")));
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

    #[tokio::test]
    async fn global_hourly_cap_sends_nothing_past_it_but_succeeds() {
        let (store, mail) = (MemStore::default(), Arc::new(CaptureMailer::default()));
        let action = RequestMagicLink::new(
            Arc::new(store.clone()),
            (
                Arc::new(crate::adapters::memory::MemRateLimiter::default()),
                2,
            ),
            mail.clone(),
            WEB.into(),
            Arc::new(opsagent_core::repo::SystemClock),
            SECRET.into(),
            Default::default(),
        );
        for n in 0..3 {
            action
                .run(input(&format!("u{n}@example.com")))
                .await
                .unwrap();
        }
        assert_eq!(mail.sent().len(), 2);
        let third = Email::parse("u2@example.com").unwrap();
        assert!(store.users().find_by_email(&third).await.unwrap().is_none());
    }

    fn closed(store: &MemStore, mail: &Arc<CaptureMailer>) -> RequestMagicLink {
        RequestMagicLink::new(
            Arc::new(store.clone()),
            (
                Arc::new(crate::adapters::memory::MemRateLimiter::default()),
                1000,
            ),
            mail.clone(),
            WEB.into(),
            Arc::new(opsagent_core::repo::SystemClock),
            SECRET.into(),
            opsagent_core::user::SignupAllowlist::parse("opsagent.dev"),
        )
    }

    #[tokio::test]
    async fn closed_domain_new_address_gets_waitlist_mail_and_no_user() {
        let (store, mail) = (MemStore::default(), Arc::new(CaptureMailer::default()));
        closed(&store, &mail)
            .run(input("Out@gmail.com"))
            .await
            .unwrap();
        let sent = mail.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].subject, "OpsAgent sign-ups are closed for now");
        assert_eq!(sent[0].to, "out@gmail.com");
        assert!(!sent[0].text.contains("token="));
        let email = Email::parse("out@gmail.com").unwrap();
        assert!(store.users().find_by_email(&email).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn closed_domain_existing_user_and_allowed_domain_get_links() {
        let (store, mail) = (MemStore::default(), Arc::new(CaptureMailer::default()));
        let old = Email::parse("old@gmail.com").unwrap();
        store.users().find_or_create_by_email(&old).await.unwrap();
        let action = closed(&store, &mail);
        action.run(input("old@gmail.com")).await.unwrap();
        action.run(input("new@opsagent.dev")).await.unwrap();
        let sent = mail.sent();
        assert_eq!(sent.len(), 2);
        assert!(sent
            .iter()
            .all(|m| m.subject.starts_with("Your OpsAgent sign-in code")));
        let email = Email::parse("new@opsagent.dev").unwrap();
        assert!(store.users().find_by_email(&email).await.unwrap().is_some());
    }
}
