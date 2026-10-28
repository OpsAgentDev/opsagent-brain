use std::{net::IpAddr, sync::Arc};

use opsagent_core::{repo::Clock, user::Email};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use super::redeem_magic_link::sign_in_entry;
use crate::{
    actions::{hit_ip, uow::UnitOfWork, RateLimiter, DAY_SECS},
    error::{AppError, AppResult},
    tokens::code_hash,
};

/// Verify attempts per client IP and per address, per window.
const CAP: i64 = 10;
const WINDOW_SECS: i64 = 900;
/// Verify attempts per address per day.
const DAY_CAP: i64 = 20;

pub struct VerifyCodeInput {
    pub email: String,
    pub code: String,
    pub client_ip: Option<IpAddr>,
}

/// Signs in with the 6-digit code from the mail: spends the matching link, once.
pub struct VerifyCode {
    uow: Arc<dyn UnitOfWork>,
    limiter: Arc<dyn RateLimiter>,
    clock: Arc<dyn Clock>,
    secret: String,
}

impl VerifyCode {
    pub fn new(
        uow: Arc<dyn UnitOfWork>,
        limiter: Arc<dyn RateLimiter>,
        clock: Arc<dyn Clock>,
        secret: String,
    ) -> Self {
        Self {
            uow,
            limiter,
            clock,
            secret,
        }
    }

    /// Counts this attempt against the IP (when known), then the address per 15 minutes and per
    /// day. Fails closed: a limiter error is also a 429.
    async fn within_caps(&self, email: &Email, ip: Option<IpAddr>) -> AppResult<()> {
        let over = || AppError::RateLimited {
            detail: "Too many attempts. Try again in a few minutes.".into(),
            retry_after_secs: WINDOW_SECS as u64,
        };
        // Fail closed: an unavailable limiter refuses rather than allowing unlimited guesses.
        let allowed = |r: AppResult<bool>| {
            r.unwrap_or_else(|e| {
                tracing::warn!(error = %e, "verify code rate limit unavailable, refusing");
                false
            })
        };
        let sha = format!("{:x}", Sha256::digest(email.as_str()));
        if ip.is_some() {
            let ok = hit_ip(
                &*self.limiter,
                "ratelimit:verify_code",
                ip,
                CAP,
                WINDOW_SECS,
            )
            .await;
            if !allowed(ok) {
                return Err(over());
            }
        }
        for (key, cap, window) in [
            (
                format!("ratelimit:verify_code:email:{sha}"),
                CAP,
                WINDOW_SECS,
            ),
            (
                format!("ratelimit:verify_code:email_day:{sha}"),
                DAY_CAP,
                DAY_SECS,
            ),
        ] {
            if !allowed(self.limiter.hit(&key, cap, window).await) {
                return Err(over());
            }
        }
        Ok(())
    }

    /// The user and the matched link's `return_to`; `Gone("code_invalid")` for a wrong, spent,
    /// expired or disabled code.
    pub async fn run(&self, input: VerifyCodeInput) -> AppResult<(Uuid, Option<String>)> {
        let invalid = || AppError::Gone("code_invalid");
        let email = Email::parse(&input.email).ok_or_else(invalid)?;
        self.within_caps(&email, input.client_ip).await?;
        let code: String = input.code.chars().filter(char::is_ascii_digit).collect();
        if code.len() != 6 {
            return Err(invalid());
        }
        let now = self.clock.now();
        let tx = self.uow.begin().await?;
        let live = tx.users().live_codes(&email, now).await?;
        // Every row is compared, so timing does not reveal which one matched.
        let mut hit = None;
        for l in &live {
            let want = code_hash(&self.secret, &l.token_hash, &code);
            if bool::from(want.as_bytes().ct_eq(l.code_hash.as_bytes())) {
                hit = Some(l);
            }
        }
        let Some(hit) = hit else {
            let ids: Vec<Uuid> = live.iter().map(|l| l.id).collect();
            tx.users().count_wrong_code(&ids).await?;
            tx.commit().await?;
            return Err(invalid());
        };
        if !tx.users().spend_code(hit.id, now).await? {
            return Err(invalid());
        }
        tx.audit().record(sign_in_entry(hit.user_id)).await?;
        tx.commit().await?;
        Ok((hit.user_id, hit.return_to.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        actions::auth::{test_support::*, MagicLinkInput, RedeemMagicLink},
        adapters::memory::{MemRateLimiter, MemStore},
        mailers::CaptureMailer,
    };
    use opsagent_core::repo::SystemClock;

    const EMAIL: &str = "code@example.com";

    fn verify(store: &MemStore) -> VerifyCode {
        VerifyCode::new(
            Arc::new(store.clone()),
            Arc::new(MemRateLimiter::default()),
            Arc::new(SystemClock),
            SECRET.into(),
        )
    }

    fn input(email: &str, code: &str) -> VerifyCodeInput {
        VerifyCodeInput {
            email: email.into(),
            code: code.into(),
            client_ip: None,
        }
    }

    async fn request(store: &MemStore, mail: &Arc<CaptureMailer>) {
        let input = MagicLinkInput {
            email: EMAIL.into(),
            client_ip: None,
            return_to: None,
        };
        request_link(store, mail).run(input).await.unwrap();
    }

    fn assert_invalid<T: std::fmt::Debug>(r: AppResult<T>) {
        assert!(matches!(r, Err(AppError::Gone("code_invalid"))), "{r:?}");
    }

    fn wrong(code: &str) -> String {
        if code == "000000" { "000001" } else { "000000" }.into()
    }

    #[tokio::test]
    async fn code_from_mail_signs_in_once() {
        let (store, mail) = (MemStore::default(), Arc::new(CaptureMailer::default()));
        request(&store, &mail).await;
        let (code, token) = (last_code(&mail), last_token(&mail));
        let v = verify(&store);
        let (user_id, to) = v.run(input(EMAIL, &code)).await.unwrap();
        assert_eq!(to, None);
        assert_one_sign_in(&store, user_id);
        assert_invalid(v.run(input(EMAIL, &code)).await);
        let redeem = RedeemMagicLink::new(Arc::new(store.clone()), Arc::new(SystemClock));
        let err = redeem.run(&token).await.unwrap_err();
        assert!(matches!(err, AppError::Gone("link_invalid")), "{err:?}");
    }

    #[tokio::test]
    async fn code_with_spaces_and_upper_case_email_works() {
        let (store, mail) = (MemStore::default(), Arc::new(CaptureMailer::default()));
        request(&store, &mail).await;
        let code = last_code(&mail);
        let v = verify(&store);
        let spaced = format!("{} {}", &code[..3], &code[3..]);
        v.run(input(&EMAIL.to_uppercase(), &spaced)).await.unwrap();
        // A dashed code works too (fresh link: the first one is spent).
        request(&store, &mail).await;
        let code = last_code(&mail);
        let dashed = format!("{}-{}", &code[..3], &code[3..]);
        v.run(input(EMAIL, &dashed)).await.unwrap();
    }

    #[tokio::test]
    async fn fifth_wrong_code_kills_code_not_link() {
        let (store, mail) = (MemStore::default(), Arc::new(CaptureMailer::default()));
        request(&store, &mail).await;
        let (code, token) = (last_code(&mail), last_token(&mail));
        let v = verify(&store);
        for _ in 0..5 {
            assert_invalid(v.run(input(EMAIL, &wrong(&code))).await);
        }
        assert_invalid(v.run(input(EMAIL, &code)).await);
        let redeem = RedeemMagicLink::new(Arc::new(store.clone()), Arc::new(SystemClock));
        redeem.run(&token).await.unwrap();
    }

    #[tokio::test]
    async fn older_mail_code_still_works() {
        let (store, mail) = (MemStore::default(), Arc::new(CaptureMailer::default()));
        request(&store, &mail).await;
        let first = last_code(&mail);
        request(&store, &mail).await;
        verify(&store).run(input(EMAIL, &first)).await.unwrap();
    }

    #[tokio::test]
    async fn verify_over_address_cap_is_too_many() {
        let (store, mail) = (MemStore::default(), Arc::new(CaptureMailer::default()));
        request(&store, &mail).await;
        let v = verify(&store);
        for _ in 0..CAP {
            assert_invalid(v.run(input(EMAIL, "000000")).await);
        }
        let err = v.run(input(EMAIL, "000000")).await.unwrap_err();
        assert!(matches!(err, AppError::RateLimited { .. }), "{err:?}");
    }

    /// Passes every 15-minute hit, so only the daily cap can refuse; or errors on every hit.
    struct DayOnly(MemRateLimiter, bool);

    #[async_trait::async_trait]
    impl RateLimiter for DayOnly {
        async fn hit(&self, key: &str, cap: i64, w: i64) -> AppResult<bool> {
            if self.1 {
                return Err(AppError::Internal("redis down".into()));
            }
            Ok(self.0.hit(key, cap, w).await? || !key.contains("email_day"))
        }
        async fn distinct(&self, k: &str, m: &str, w: i64) -> AppResult<i64> {
            self.0.distinct(k, m, w).await
        }
        async fn clear(&self, k: &str) -> AppResult<()> {
            self.0.clear(k).await
        }
        async fn forget(&self, k: &str, m: &str) -> AppResult<()> {
            self.0.forget(k, m).await
        }
    }

    fn with_limiter(store: &MemStore, l: DayOnly) -> VerifyCode {
        VerifyCode::new(
            Arc::new(store.clone()),
            Arc::new(l),
            Arc::new(SystemClock),
            SECRET.into(),
        )
    }

    #[tokio::test]
    async fn twenty_first_attempt_in_a_day_is_too_many() {
        let store = MemStore::default();
        let v = with_limiter(&store, DayOnly(MemRateLimiter::default(), false));
        for _ in 0..DAY_CAP {
            assert_invalid(v.run(input(EMAIL, "000000")).await);
        }
        let err = v.run(input(EMAIL, "000000")).await.unwrap_err();
        assert!(matches!(err, AppError::RateLimited { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn limiter_error_fails_closed_with_429() {
        let store = MemStore::default();
        let v = with_limiter(&store, DayOnly(MemRateLimiter::default(), true));
        let err = v.run(input(EMAIL, "000000")).await.unwrap_err();
        assert!(matches!(err, AppError::RateLimited { .. }), "{err:?}");
    }
}
