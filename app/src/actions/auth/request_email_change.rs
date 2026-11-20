//! The first half of changing the sign-in address: a code mailed to the new address. The second
//! half is `ConfirmEmailChange`.
use std::{net::IpAddr, sync::Arc};

use axum::http::StatusCode;
use chrono::Duration;
use opsagent_core::{
    repo::Clock,
    user::{Email, SignupAllowlist},
};
use uuid::Uuid;

use super::request_magic_link::{MailCaps, PER_EMAIL};
use crate::{
    actions::{uow::UnitOfWork, RateLimiter, HOUR_SECS},
    error::{AppError, AppResult},
    mailers::{magic_link as mail, Mailer},
    tokens::{code_hash, hash_token, new_code, new_token},
};

pub struct RequestEmailChange {
    users: Arc<dyn UnitOfWork>,
    limiter: Arc<dyn RateLimiter>,
    caps: MailCaps,
    mailer: Arc<dyn Mailer>,
    clock: Arc<dyn Clock>,
    /// Keys the stored code hashes (`SESSION_SECRET`).
    secret: String,
    signup: SignupAllowlist,
}

impl RequestEmailChange {
    pub fn new(
        users: Arc<dyn UnitOfWork>,
        caps: (Arc<dyn RateLimiter>, i64),
        mailer: Arc<dyn Mailer>,
        clock: Arc<dyn Clock>,
        secret: String,
        signup: SignupAllowlist,
    ) -> Self {
        Self {
            users,
            limiter: caps.0.clone(),
            caps: MailCaps::new(caps),
            mailer,
            clock,
            secret,
            signup,
        }
    }

    /// The user's own hourly budget, then the sign-in mail caps for the new address. Fails
    /// closed: a limiter error is also a 429.
    async fn within_caps(&self, user_id: Uuid, email: &Email, ip: Option<IpAddr>) -> AppResult<()> {
        let key = format!("ratelimit:email_change:user:{user_id}");
        let under = match self.limiter.hit(&key, PER_EMAIL, HOUR_SECS).await {
            Ok(true) => self.caps.under(email, ip).await,
            other => other,
        };
        if under.unwrap_or_else(|e| {
            tracing::warn!(error = %e, "email change rate limit unavailable, refusing");
            false
        }) {
            return Ok(());
        }
        Err(AppError::RateLimited {
            detail: "Too many codes requested. Try again in an hour.".into(),
            retry_after_secs: HOUR_SECS as u64,
        })
    }

    /// Mails a code to `raw` unless it cannot be the user's new address. An address that
    /// already signs in to an account gets a notice instead of a code and the caller is told
    /// nothing, so the answer never reveals whether an address has an account.
    pub async fn run(&self, user_id: Uuid, raw: &str, ip: Option<IpAddr>) -> AppResult<()> {
        let refused = |code, detail: &str| AppError::Refused {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            code,
            detail: detail.into(),
        };
        let email = Email::parse(raw)
            .ok_or_else(|| AppError::Invalid("that is not a usable email address".into()))?;
        let users = self.users.users();
        let user = users.get(user_id).await?;
        let user = user.ok_or(AppError::Unauthenticated)?;
        if user.email == email {
            return Err(refused(
                "email_unchanged",
                "That is already your sign-in email.",
            ));
        }
        // By domain alone, before any lookup, so it says nothing about accounts.
        if !self.signup.allows(&email) {
            return Err(refused(
                "email_not_allowed",
                "OpsAgent is not open to addresses on that domain yet.",
            ));
        }
        self.within_caps(user_id, &email, ip).await?;
        // An address that only ever asked for a sign-in link is not an account: it stays free.
        let taken = match users.find_by_email(&email).await? {
            Some(other) => !users.is_unproven(other.id).await?,
            None => false,
        };
        let sent = if taken {
            self.mailer
                .send(mail::email_change_taken(email.as_str()))
                .await
        } else {
            // Never mailed or shown: it only salts the code hash, like a sign-in link's.
            let token_hash = hash_token(&new_token());
            let code = new_code();
            let expires = self.clock.now() + Duration::minutes(15);
            let hash = code_hash(&self.secret, &token_hash, &code);
            users
                .issue_email_change(user_id, &email, &token_hash, &hash, expires)
                .await?;
            self.mailer
                .send(mail::email_change_code(email.as_str(), &code))
                .await
        };
        if let Err(e) = sent {
            tracing::error!(error = %e, "email change mail failed");
        }
        Ok(())
    }
}
