//! Billing gating (billing.md, Gating; PRD 7.9), all of it off unless `BILLING_ENFORCED`: an
//! organisation not in good standing is read-only and gets no scheduled work, a trial has one
//! billable connection, and a tier's member and integration limits hold for new ones.
use std::sync::Arc;

use axum::http::StatusCode;
use opsagent_core::{
    billing::{plan_limits, BillingStatus, PlanLimits},
    repo::Clock,
};
use uuid::Uuid;

use crate::{
    actions::uow::UnitOfWork,
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
    pub async fn of(repos: &dyn UnitOfWork, organisation_id: Uuid) -> AppResult<Self> {
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

#[derive(Clone)]
pub struct BillingGate {
    uow: Arc<dyn UnitOfWork>,
    enforced: bool,
    clock: Arc<dyn Clock>,
}

impl BillingGate {
    pub fn new(uow: Arc<dyn UnitOfWork>, enforced: bool, clock: Arc<dyn Clock>) -> Self {
        Self {
            uow,
            enforced,
            clock,
        }
    }

    /// `true` when the organisation's scans, deliveries and writes are stopped: enforced and
    /// not trialing, active or past due under 7 days.
    pub async fn gated(&self, organisation_id: Uuid) -> AppResult<bool> {
        if !self.enforced {
            return Ok(false);
        }
        let b = self.uow.billing().billing(organisation_id).await?;
        Ok(!b.status.in_good_standing())
    }

    /// 402 `billing_required` when `gated`.
    pub async fn require_writable(&self, organisation_id: Uuid) -> AppResult<()> {
        match self.gated(organisation_id).await? {
            true => Err(payment_required(
                BILLING_REQUIRED,
                "This organisation is read-only until billing is set up.",
            )),
            false => Ok(()),
        }
    }

    /// 402 `trial_limit` when a trialing organisation already has its one billable connection.
    pub async fn require_connection_room(&self, organisation_id: Uuid) -> AppResult<()> {
        if !self.enforced {
            return Ok(());
        }
        let b = self.uow.billing().billing(organisation_id).await?;
        if b.status != BillingStatus::Trialing {
            return Ok(());
        }
        let since = b.subscription.and_then(|s| s.current_period_start);
        let since = since.unwrap_or_else(|| self.clock.now());
        let billable = self.uow.billing().billable_count(organisation_id, since);
        match billable.await? >= 1 {
            true => Err(payment_required(
                TRIAL_LIMIT,
                "A trial covers one connection; subscribe to add more.",
            )),
            false => Ok(()),
        }
    }

    /// 402 `plan_limit` when the organisation is over its tier's member or integration limit,
    /// or (`adding_member`) already at its member limit.
    pub async fn require_plan_room(
        &self,
        organisation_id: Uuid,
        adding_member: bool,
    ) -> AppResult<()> {
        if !self.enforced {
            return Ok(());
        }
        let b = self.uow.billing().billing(organisation_id).await?;
        let Some(limits) = b.subscription.and_then(|s| s.tier).map(plan_limits) else {
            return Ok(());
        };
        let u = Usage::of(&*self.uow, organisation_id).await?;
        let at_members = limits.members.is_some_and(|c| u.members >= c as usize);
        match u.over(limits) || (adding_member && at_members) {
            true => Err(payment_required(
                PLAN_LIMIT,
                "Your plan's member or integration limit is reached; upgrade to add more.",
            )),
            false => Ok(()),
        }
    }
}
