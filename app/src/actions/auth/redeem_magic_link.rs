use std::sync::Arc;

use opsagent_core::{audit::AuditEntry, repo::Clock};
use uuid::Uuid;

use crate::{
    actions::uow::UnitOfWork,
    error::{AppError, AppResult},
    tokens::hash_token,
};

/// Spends a magic link, once, and records the sign-in.
pub struct RedeemMagicLink {
    uow: Arc<dyn UnitOfWork>,
    clock: Arc<dyn Clock>,
}

impl RedeemMagicLink {
    pub fn new(uow: Arc<dyn UnitOfWork>, clock: Arc<dyn Clock>) -> Self {
        Self { uow, clock }
    }

    /// The link's user and its stored `return_to`; `Gone("link_invalid")` if it is unknown,
    /// expired or already used.
    pub async fn run(&self, token: &str) -> AppResult<(Uuid, Option<String>)> {
        let tx = self.uow.begin().await?;
        let (user_id, return_to) = tx
            .users()
            .consume_magic_link(&hash_token(token), self.clock.now())
            .await?
            .ok_or(AppError::Gone("link_invalid"))?;
        tx.audit().record(sign_in_entry(user_id)).await?;
        tx.commit().await?;
        Ok((user_id, return_to))
    }
}

pub(super) fn sign_in_entry(user_id: Uuid) -> AuditEntry {
    AuditEntry::member(
        None,
        user_id,
        "auth.sign_in",
        Some(("user", user_id.to_string())),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::{Duration, Utc};
    use opsagent_core::repo::SystemClock;

    use super::*;
    use crate::{
        actions::auth::{test_support::*, MagicLinkInput, RequestMagicLink},
        adapters::memory::{FixedClock, MemRateLimiter, MemStore},
        mailers::CaptureMailer,
    };

    #[tokio::test]
    async fn redeem_twice_is_gone_link_invalid() {
        let (store, mail) = (MemStore::default(), Arc::new(CaptureMailer::default()));
        let input = MagicLinkInput {
            email: "once@example.com".into(),
            client_ip: None,
            return_to: None,
        };
        request_link(&store, &mail).run(input).await.unwrap();
        let token = last_token(&mail);
        let redeem = RedeemMagicLink::new(Arc::new(store.clone()), Arc::new(SystemClock));
        let (user_id, _) = redeem.run(&token).await.unwrap();
        assert_one_sign_in(&store, user_id);
        let again = redeem.run(&token).await.unwrap_err();
        assert!(matches!(again, AppError::Gone("link_invalid")), "{again:?}");
        let unknown = redeem.run("no-such-token").await.unwrap_err();
        assert!(matches!(unknown, AppError::Gone("link_invalid")));
        // Refusals record nothing.
        assert_one_sign_in(&store, user_id);
    }

    #[tokio::test]
    async fn fifteen_minute_old_link_is_gone() {
        let (store, mail) = (MemStore::default(), Arc::new(CaptureMailer::default()));
        let issued = Utc::now();
        let at =
            |mins| -> Arc<dyn Clock> { Arc::new(FixedClock(issued + Duration::minutes(mins))) };
        let request = RequestMagicLink::new(
            Arc::new(store.clone()),
            Arc::new(MemRateLimiter::default()),
            mail.clone(),
            WEB.into(),
            at(0),
        );
        let input = MagicLinkInput {
            email: "late@example.com".into(),
            client_ip: None,
            return_to: None,
        };
        request.run(input).await.unwrap();
        let token = last_token(&mail);
        let late = RedeemMagicLink::new(Arc::new(store.clone()), at(15));
        let err = late.run(&token).await.unwrap_err();
        assert!(matches!(err, AppError::Gone("link_invalid")), "{err:?}");
        // Still unused: a minute earlier it would have worked.
        let in_time = RedeemMagicLink::new(Arc::new(store.clone()), at(14));
        in_time.run(&token).await.unwrap();
    }
}
