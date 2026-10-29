//! Billing gating (billing.md, Gating; PRD 7.9), all of it off unless `BILLING_ENFORCED`: an
//! organisation not in good standing is read-only and gets no scheduled work, a trial has one
//! billable connection, and a tier's member and integration limits hold for new ones.
use std::sync::Arc;

use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use opsagent_core::{
    billing::{plan_limits, BillingStatus, PlanLimits},
    connection::{Connection, ConnectionStatus as S},
    repo::Clock,
};
use uuid::Uuid;

use crate::{
    actions::uow::Repos,
    error::{AppError, AppResult},
};

pub const BILLING_REQUIRED: &str = "billing_required";
pub const TRIAL_LIMIT: &str = "trial_limit";
pub const PLAN_LIMIT: &str = "plan_limit";

fn payment_required(code: &'static str, detail: &str) -> AppError {
    AppError::Refused {
        status: StatusCode::PAYMENT_REQUIRED,
        code,
        detail: detail.into(),
    }
}

/// An organisation's members and active integrations, against its tier's limits.
pub(super) struct Usage {
    pub members: usize,
    pub integrations: usize,
}

impl Usage {
    pub async fn of(repos: &dyn Repos, organisation_id: Uuid) -> AppResult<Self> {
        let members = repos.orgs().members(organisation_id).await?.len();
        let integrations = repos.integrations().list(organisation_id).await?;
        let integrations = integrations.iter().filter(|i| i.status == "active").count();
        Ok(Self {
            members,
            integrations,
        })
    }

    /// More members or active integrations than `l` allows.
    pub fn over(&self, l: PlanLimits) -> bool {
        let over = |cap: Option<u32>, n: usize| cap.is_some_and(|c| n > c as usize);
        over(l.members, self.members) || over(l.integrations, self.integrations)
    }
}

/// What a plan-limit check is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seat {
    /// A new invite: members plus pending invites must stay under the member limit.
    Invite,
    /// An accepted invite: members must stay under the member limit.
    Member,
    /// A Slack install: it replaces the one Slack integration, so only "already over" refuses.
    Integration,
}

/// The checks take the repositories to read from, so a caller can run them inside its
/// transaction (`AcceptInvite`, the verify outcome) or on the pool.
#[derive(Clone)]
pub struct BillingGate {
    enforced: bool,
    clock: Arc<dyn Clock>,
}

impl BillingGate {
    pub fn new(enforced: bool, clock: Arc<dyn Clock>) -> Self {
        Self { enforced, clock }
    }

    pub fn enforced(&self) -> bool {
        self.enforced
    }

    /// `true` when the organisation's scans, deliveries and writes are stopped: enforced and
    /// not in good standing (`OrgBilling::in_good_standing`).
    pub async fn gated(&self, r: &dyn Repos, organisation_id: Uuid) -> AppResult<bool> {
        if !self.enforced {
            return Ok(false);
        }
        let b = r.billing().billing(organisation_id).await?;
        Ok(!b.in_good_standing(self.clock.now()))
    }

    /// 402 `billing_required` when `gated`.
    pub async fn require_writable(&self, r: &dyn Repos, organisation_id: Uuid) -> AppResult<()> {
        match self.gated(r, organisation_id).await? {
            true => Err(payment_required(
                BILLING_REQUIRED,
                "This organisation is read-only until billing is set up.",
            )),
            false => Ok(()),
        }
    }

    /// The trial's stored period start when enforced and trialing (`None` otherwise).
    async fn trial_since(
        &self,
        r: &dyn Repos,
        organisation_id: Uuid,
    ) -> AppResult<Option<DateTime<Utc>>> {
        if !self.enforced {
            return Ok(None);
        }
        let b = r.billing().billing(organisation_id).await?;
        if b.status != BillingStatus::Trialing {
            return Ok(None);
        }
        let since = b.subscription.and_then(|s| s.current_period_start);
        Ok(Some(since.unwrap_or_else(|| self.clock.now())))
    }

    /// `true` when connecting `account` (`provider:account`) would make the trialing
    /// organisation pay for more than one distinct account this period; reconnecting the
    /// account it already has is allowed.
    pub async fn trial_refuses_account(
        &self,
        r: &dyn Repos,
        organisation_id: Uuid,
        account: &str,
    ) -> AppResult<bool> {
        let Some(since) = self.trial_since(r, organisation_id).await? else {
            return Ok(false);
        };
        let mut paid = r
            .billing()
            .billable_accounts(organisation_id, Some(since))
            .await?;
        paid.retain(|a| a != account);
        Ok(!paid.is_empty())
    }

    /// 402 `trial_limit` when the trialing organisation already has a live connection
    /// (`connected`, `degraded`, `revoked`, or one still `pending` or `verifying`).
    pub async fn require_connection_room(
        &self,
        r: &dyn Repos,
        organisation_id: Uuid,
    ) -> AppResult<()> {
        if self.trial_since(r, organisation_id).await?.is_none() {
            return Ok(());
        }
        let live = |c: &Connection| {
            matches!(
                c.status,
                S::Connected | S::Degraded | S::Revoked | S::Pending | S::Verifying
            )
        };
        match r
            .connections()
            .list(organisation_id)
            .await?
            .iter()
            .any(live)
        {
            true => Err(trial_limit()),
            false => Ok(()),
        }
    }

    /// 402 `plan_limit` when the organisation is over its tier's member or integration limit,
    /// or `seat` would take it past its member limit.
    pub async fn require_plan_room(
        &self,
        r: &dyn Repos,
        organisation_id: Uuid,
        seat: Seat,
    ) -> AppResult<()> {
        if !self.enforced {
            return Ok(());
        }
        let b = r.billing().billing(organisation_id).await?;
        let Some(limits) = b.subscription.and_then(|s| s.tier).map(plan_limits) else {
            return Ok(());
        };
        let u = Usage::of(r, organisation_id).await?;
        let seats = match seat {
            Seat::Invite => {
                let pending = r.orgs().pending_invites(organisation_id, self.clock.now());
                Some(u.members + pending.await? as usize)
            }
            Seat::Member => Some(u.members),
            Seat::Integration => None,
        };
        let full = seats.is_some_and(|n| limits.members.is_some_and(|c| n >= c as usize));
        match u.over(limits) || full {
            true => Err(payment_required(
                PLAN_LIMIT,
                "Your plan's member or integration limit is reached; upgrade to add more.",
            )),
            false => Ok(()),
        }
    }
}

/// 402 `trial_limit`.
pub fn trial_limit() -> AppError {
    payment_required(
        TRIAL_LIMIT,
        "A trial covers one connection; subscribe to add more.",
    )
}
