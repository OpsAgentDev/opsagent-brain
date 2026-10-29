use std::sync::Arc;

use axum::http::StatusCode;
use opsagent_core::{
    audit::AuditEntry,
    org::{Organisation, Role},
    repo::{Clock, RepoError},
};
use uuid::Uuid;

use crate::{
    actions::{
        billing::{BillingGate, Seat},
        uow::{Tx, UnitOfWork},
    },
    error::{AppError, AppResult},
    tokens::hash_token,
};

/// Accepts an invite for the signed-in user; the organisation and the role held. One
/// transaction: a refused accept leaves the invite pending. A new member of a read-only
/// organisation gets 402 `billing_required`, one past the tier's member limit `plan_limit`.
pub struct AcceptInvite {
    uow: Arc<dyn UnitOfWork>,
    clock: Arc<dyn Clock>,
    gate: BillingGate,
}

impl AcceptInvite {
    pub fn new(uow: Arc<dyn UnitOfWork>, clock: Arc<dyn Clock>, gate: BillingGate) -> Self {
        Self { uow, clock, gate }
    }

    pub async fn run(&self, user_id: Uuid, token: &str) -> AppResult<(Organisation, Role)> {
        let gone = || AppError::Gone("invite_invalid");
        let tx = self.uow.begin().await?;
        let inv = tx
            .orgs()
            .take_invite(&hash_token(token), self.clock.now())
            .await?
            .ok_or_else(gone)?;
        let user = tx
            .users()
            .get(user_id)
            .await?
            .ok_or(AppError::Unauthenticated)?;
        if inv.email != user.email {
            return Err(AppError::Refused {
                status: StatusCode::FORBIDDEN,
                code: "invite_email_mismatch",
                detail: "This invite was sent to a different email address.".into(),
            });
        }
        let org = tx
            .orgs()
            .get(inv.organisation_id)
            .await?
            .filter(|o| o.deleted_at.is_none())
            .ok_or_else(gone)?;
        if tx.orgs().membership(&org.slug, user_id).await?.is_none() {
            // Serialises concurrent accepts, so two cannot both take the last seat.
            tx.orgs().lock(org.id).await?;
            self.gate.require_writable(tx.as_ref(), org.id).await?;
            let seat = Seat::Member;
            self.gate
                .require_plan_room(tx.as_ref(), org.id, seat)
                .await?;
        }
        let role = join(tx.as_ref(), &org, user_id, inv.role).await?;
        let target = Some(("invite", inv.id.to_string()));
        let entry = AuditEntry::member(Some(org.id), user_id, "invite.accept", target);
        tx.audit().record(entry).await?;
        tx.commit().await?;
        Ok((org, role))
    }
}

/// The role held after joining. An existing membership keeps its role, also when a concurrent
/// accept (a double submit) adds it first: the insert reports the conflict without aborting
/// the transaction.
async fn join(tx: &dyn Tx, org: &Organisation, user_id: Uuid, role: Role) -> AppResult<Role> {
    if let Some((_, m)) = tx.orgs().membership(&org.slug, user_id).await? {
        return Ok(m.role);
    }
    match tx.orgs().add_member(org.id, user_id, role).await {
        Ok(m) => Ok(m.role),
        Err(RepoError::Conflict("member")) => {
            let held = tx.orgs().membership(&org.slug, user_id).await?;
            let missing = || RepoError::Storage("member missing after conflict".into());
            Ok(held.ok_or_else(missing)?.1.role)
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};

    use super::*;
    use crate::{
        actions::{billing::BillingGate, members::InviteMember, orgs::test_support::*},
        adapters::memory::{FixedClock, MemStore},
        mailers::CaptureMailer,
    };

    #[tokio::test]
    async fn accept_expired_invite_gone_invite_invalid() {
        let (store, mail) = (MemStore::default(), Arc::new(CaptureMailer::default()));
        let (owner, org) = owned_org(&store, "boss@example.com", "Acme").await;
        let scope = scope(&store, &org, &owner).await;
        let sent_at = Utc::now();
        let at = |days| -> Arc<dyn Clock> { Arc::new(FixedClock(sent_at + Duration::days(days))) };
        let invite = InviteMember::new(
            Arc::new(store.clone()),
            mail.clone(),
            "https://web.test".into(),
            at(0),
            BillingGate::new(false, at(0)),
        );
        invite
            .run(&scope, owner.id, "new@example.com", "member")
            .await
            .unwrap();
        let text = mail.sent().pop().unwrap().text;
        let token = text
            .split("/invites/")
            .nth(1)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap();
        let invitee = user(&store, "new@example.com").await;

        let late = AcceptInvite::new(
            Arc::new(store.clone()),
            at(8),
            BillingGate::new(false, at(8)),
        );
        let err = late.run(invitee.id, token).await.unwrap_err();
        assert!(matches!(err, AppError::Gone("invite_invalid")), "{err:?}");

        // Still pending: within the week it is accepted.
        let in_time = AcceptInvite::new(
            Arc::new(store.clone()),
            at(6),
            BillingGate::new(false, at(6)),
        );
        let (joined, role) = in_time.run(invitee.id, token).await.unwrap();
        assert_eq!((joined.id, role), (org.id, Role::Member));
    }
}
