use std::sync::Arc;

use chrono::Duration;
use opsagent_core::{
    audit::AuditEntry,
    org::{Invite, Role},
    repo::Clock,
    user::Email,
};
use uuid::Uuid;

use crate::{
    actions::{
        billing::{BillingGate, Seat},
        orgs::OrgScope,
        uow::UnitOfWork,
        RateLimiter, DAY_SECS,
    },
    error::{AppError, AppResult},
    mailers::{magic_link as mail, Mailer},
    tokens::{hash_token, new_token},
};

/// Invites one organisation may send per day, so an owner cannot use us as a mail cannon.
pub const INVITES_PER_ORG_PER_DAY: i64 = 20;

/// Creates a 7-day invite and mails its link (`{web_base_url}/invites/{token}`). Owners only;
/// 402 `plan_limit` when members plus pending invites reach the tier's member limit; 429 after
/// `INVITES_PER_ORG_PER_DAY` invites in a day (refused when the limiter is down).
pub struct InviteMember {
    uow: Arc<dyn UnitOfWork>,
    mailer: Arc<dyn Mailer>,
    web_base_url: String,
    clock: Arc<dyn Clock>,
    gate: BillingGate,
    limiter: Arc<dyn RateLimiter>,
}

impl InviteMember {
    pub fn new(
        uow: Arc<dyn UnitOfWork>,
        mailer: Arc<dyn Mailer>,
        web_base_url: String,
        clock: Arc<dyn Clock>,
        gate: BillingGate,
        limiter: Arc<dyn RateLimiter>,
    ) -> Self {
        Self {
            uow,
            mailer,
            web_base_url,
            clock,
            gate,
            limiter,
        }
    }

    pub async fn run(
        &self,
        scope: &OrgScope,
        actor: Uuid,
        email: &str,
        role: &str,
    ) -> AppResult<Invite> {
        scope.require_owner()?;
        let email = Email::parse(email).ok_or_else(|| AppError::Invalid("invalid email".into()))?;
        let role = Role::parse(role)
            .ok_or_else(|| AppError::Invalid("role must be owner or member".into()))?;
        let org = &scope.organisation;
        let seat = Seat::Invite;
        self.gate
            .require_plan_room(&*self.uow, org.id, seat)
            .await?;
        let key = format!("ratelimit:invite:org:{}", org.id);
        if !self
            .limiter
            .hit(&key, INVITES_PER_ORG_PER_DAY, DAY_SECS)
            .await?
        {
            return Err(AppError::RateLimited {
                detail: "Too many invites today. Try again tomorrow.".into(),
                retry_after_secs: DAY_SECS as u64,
            });
        }
        let token = new_token();
        let expires = self.clock.now() + Duration::days(7);
        let tx = self.uow.begin().await?;
        let row = tx
            .orgs()
            .insert_invite(org.id, &email, role, &hash_token(&token), expires)
            .await?;
        let target = Some(("invite", row.id.to_string()));
        let entry = AuditEntry::member(Some(org.id), actor, "invite.create", target);
        tx.audit().record(entry).await?;
        tx.commit().await?;
        let link = format!("{}/invites/{token}", self.web_base_url);
        let sent = self
            .mailer
            .send(mail::invite(email.as_str(), &org.name, &link));
        if let Err(e) = sent.await {
            tracing::error!(error = %e, "invite mail failed");
        }
        Ok(row)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        actions::orgs::test_support::*,
        adapters::memory::{FixedClock, MemRateLimiter, MemStore},
        mailers::CaptureMailer,
    };

    #[tokio::test]
    async fn the_21st_invite_in_a_day_is_refused_and_other_orgs_are_unaffected() {
        let store = MemStore::default();
        let clock: Arc<dyn Clock> = Arc::new(FixedClock(chrono::Utc::now()));
        let invite = InviteMember::new(
            Arc::new(store.clone()),
            Arc::new(CaptureMailer::default()),
            "https://web.test".into(),
            clock.clone(),
            BillingGate::new(false, clock),
            Arc::new(MemRateLimiter::default()),
        );
        let (owner, org) = owned_org(&store, "boss@example.com", "Acme").await;
        let scope1 = scope(&store, &org, &owner).await;
        for i in 0..INVITES_PER_ORG_PER_DAY {
            let to = format!("new{i}@example.com");
            invite.run(&scope1, owner.id, &to, "member").await.unwrap();
        }
        let over = invite
            .run(&scope1, owner.id, "late@example.com", "member")
            .await;
        assert!(
            matches!(over, Err(AppError::RateLimited { .. })),
            "{over:?}"
        );

        let (owner2, org2) = owned_org(&store, "boss2@example.com", "Other").await;
        let scope2 = scope(&store, &org2, &owner2).await;
        invite
            .run(&scope2, owner2.id, "x@example.com", "member")
            .await
            .unwrap();
    }
}
