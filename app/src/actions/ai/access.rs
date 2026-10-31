//! `AiAccess`: who pays for a call (dashboard-ai.md, Who pays), the quota and ceiling checks,
//! and the call itself (its failures: `failures.rs`; metering: `meter.rs`).
use std::sync::Arc;

use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use opsagent_core::{
    ai::{
        period_quota, quota_period, KeySource, KeyStatus, ModelKey, ModelRole, Purpose, RoleModels,
        Slot,
    },
    billing::OrgBilling,
    model::{AiProvider, ModelError, ModelProvider, ModelRequest, ModelTurn, TextSink},
    repo::Clock,
};
use opsagent_secrets::Kek;
use sea_orm::prelude::Decimal;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    failures::AiCallError, notices::Notices, open_key, refused, role_model, AiSettings,
    AI_DISABLED, AI_QUOTA_REACHED,
};
use crate::{
    actions::{
        orgs::OrgScope,
        uow::{Repos, UnitOfWork},
    },
    adapters::model::ModelProviders,
    config::model_price,
    error::{AppError, AppResult},
};

/// Who pays for one call and with which model. No `Debug`: it holds the key.
pub struct CallPlan {
    pub provider: AiProvider,
    pub source: KeySource,
    pub model: String,
    /// The BYOK key's id; `None` on OpsAgent's key.
    pub key_id: Option<Uuid>,
    pub(super) role: ModelRole,
    pub(super) api_key: Zeroizing<String>,
}

/// One model connection, OpsAgent's or an organisation's. No `Debug`: it holds the key.
#[derive(Clone)]
pub struct Conn {
    pub style: AiProvider,
    pub source: KeySource,
    pub slot: Slot,
    /// The BYOK key's id; `None` on OpsAgent's connections.
    pub key_id: Option<Uuid>,
    pub base_url: String,
    pub base_host: Option<String>,
    /// A customer-supplied URL, checked on every call. OpsAgent's own are trusted.
    pub custom: bool,
    pub models: RoleModels,
    pub(super) api_key: Zeroizing<String>,
}

/// The organisation's AI state as `GET /orgs/{org}/ai` reports it.
#[derive(Debug, Clone, PartialEq)]
pub struct AiStatus {
    pub enabled: bool,
    /// `ready`, or the code a call would end with now.
    pub state: &'static str,
    /// Who would pay: the BYOK key when set, else OpsAgent's key when configured.
    pub source: Option<KeySource>,
    /// OpsAgent-key credits used this period.
    pub used: Decimal,
    pub quota: Decimal,
    pub topup_balance: Decimal,
    pub period: (DateTime<Utc>, DateTime<Utc>),
    /// BYOK credits this calendar month (UTC).
    pub byok_used_this_month: Decimal,
    /// The BYOK key's models are unpriced, so its credits are estimates.
    pub estimated: bool,
    pub key: Option<ModelKey>,
    /// Credits per calendar month (UTC) on BYOK; `None` is no ceiling.
    pub ceiling: Option<Decimal>,
    pub topup_available: bool,
}

/// Everything the who-pays table and the status read, at one moment.
struct Snapshot {
    enabled: bool,
    key: Option<ModelKey>,
    ceiling: Option<Decimal>,
    quota: Quota,
    topup: Decimal,
    byok_month: Decimal,
}

pub(super) struct Quota {
    pub quota: Decimal,
    pub period: (DateTime<Utc>, DateTime<Utc>),
    pub used: Decimal,
}

enum Payer {
    Byok(ModelKey),
    OpsAgent,
}

pub struct AiAccess {
    pub(super) uow: Arc<dyn UnitOfWork>,
    pub(super) kek: Arc<dyn Kek>,
    pub(super) models: ModelProviders,
    pub(super) notices: Notices,
    pub(super) clock: Arc<dyn Clock>,
    pub(super) s: AiSettings,
}

impl AiAccess {
    pub fn new(
        uow: Arc<dyn UnitOfWork>,
        kek: Arc<dyn Kek>,
        models: ModelProviders,
        notices: Notices,
        clock: Arc<dyn Clock>,
        s: AiSettings,
    ) -> Self {
        Self {
            uow,
            kek,
            models,
            notices,
            clock,
            s,
        }
    }

    /// Who pays for a `role` call now, after the quota (OpsAgent's key) or ceiling (BYOK)
    /// check. 409 `ai_disabled`, 502 `ai_key_failing`, 402 `ai_quota_reached`, 503
    /// `ai_unavailable`.
    pub async fn plan(&self, org: Uuid, role: ModelRole) -> AppResult<CallPlan> {
        let snap = self.snapshot(org).await?;
        Ok(match self.payer(&snap)? {
            Payer::Byok(k) => CallPlan {
                provider: k.provider,
                source: KeySource::Byok,
                model: role_model(&k, role).to_owned(),
                key_id: Some(k.id),
                role,
                api_key: open_key(&*self.uow, &*self.kek, &k).await?,
            },
            Payer::OpsAgent => {
                let c = self.s.opsagent.as_ref().ok_or(AiCallError::Unavailable)?;
                CallPlan {
                    provider: c.style,
                    source: KeySource::OpsAgent,
                    model: match role {
                        ModelRole::Routine => c.models.routine.clone(),
                        ModelRole::Chat => c.models.chat.clone(),
                    },
                    key_id: None,
                    role,
                    api_key: c.api_key.clone(),
                }
            }
        })
    }

    pub async fn status(&self, scope: &OrgScope) -> AppResult<AiStatus> {
        let snap = self.snapshot(scope.organisation.id).await?;
        let state = match self.payer(&snap) {
            Ok(_) => "ready",
            Err(AppError::Refused { code, .. }) => code,
            Err(e) => return Err(e),
        };
        let source = match (&snap.key, &self.s.opsagent) {
            (Some(_), _) => Some(KeySource::Byok),
            (None, Some(_)) => Some(KeySource::OpsAgent),
            (None, None) => None,
        };
        let estimated = snap.key.as_ref().is_some_and(|k| {
            [&k.models.routine, &k.models.chat]
                .iter()
                .any(|m| model_price(m).is_none())
        });
        Ok(AiStatus {
            enabled: snap.enabled,
            state,
            source,
            used: snap.quota.used,
            quota: snap.quota.quota,
            topup_balance: snap.topup,
            period: snap.quota.period,
            byok_used_this_month: snap.byok_month,
            estimated,
            key: snap.key,
            ceiling: snap.ceiling,
            topup_available: self.s.topups,
        })
    }

    async fn snapshot(&self, org: Uuid) -> AppResult<Snapshot> {
        let ai = self.uow.ai();
        let (since, until) = quota_period(&OrgBilling::default(), self.clock.now());
        Ok(Snapshot {
            enabled: ai.enabled(org).await?,
            key: ai.keys(org).await?.primary,
            ceiling: ai.credit_ceiling(org).await?,
            quota: self.quota(&*self.uow, org).await?,
            topup: ai.topup_balance(org).await?,
            byok_month: ai.credits_used(org, KeySource::Byok, since, until).await?,
        })
    }

    /// The period's quota on OpsAgent's key and the credits used in it so far.
    pub(super) async fn quota(&self, repos: &dyn Repos, org: Uuid) -> AppResult<Quota> {
        let b = repos.billing().billing(org).await?;
        let quota = Decimal::from(period_quota(&b, self.s.billing_enforced));
        let period = quota_period(&b, self.clock.now());
        let ai = repos.ai();
        let used = ai.credits_used(org, KeySource::OpsAgent, period.0, period.1);
        Ok(Quota {
            quota,
            period,
            used: used.await?,
        })
    }

    /// The who-pays table, first match wins.
    fn payer(&self, snap: &Snapshot) -> AppResult<Payer> {
        if !snap.enabled {
            let detail = "Dashboard AI is off for this organisation.";
            return Err(refused(StatusCode::CONFLICT, AI_DISABLED, detail));
        }
        if let Some(k) = &snap.key {
            // An outage key is still tried: its next success clears it.
            if k.status == KeyStatus::Failing {
                return Err(AiCallError::KeyFailing.into());
            }
            if snap.ceiling.is_some_and(|c| snap.byok_month >= c) {
                return Err(quota_reached("Your monthly credit ceiling is reached."));
            }
            return Ok(Payer::Byok(k.clone()));
        }
        if self.s.opsagent.is_none() {
            return Err(AiCallError::Unavailable.into());
        }
        let q = &snap.quota;
        if (q.quota - q.used).max(Decimal::ZERO) + snap.topup <= Decimal::ZERO {
            return Err(quota_reached("This period's AI credits are used up."));
        }
        Ok(Payer::OpsAgent)
    }

    /// One model call on `plan`, metered. Text deltas go to `sink` as they arrive.
    pub async fn call(
        &self,
        scope: &OrgScope,
        plan: &CallPlan,
        purpose: Purpose,
        mut req: ModelRequest,
        sink: &mut dyn TextSink,
    ) -> Result<ModelTurn, AiCallError> {
        let provider = self.models.get(plan.provider);
        let org = scope.organisation.id;
        req.model = plan.model.clone();
        self.recheck(org, plan).await?;
        let turn = match self.attempt(&*provider, plan, &req, sink).await {
            Err(ModelError::ModelGone) if plan.source == KeySource::Byok => {
                req.model = self.replace_model(scope, plan, &*provider).await?;
                self.recheck(org, plan).await?;
                self.attempt(&*provider, plan, &req, sink).await
            }
            r => r,
        };
        let turn = match turn {
            Ok(t) => t,
            Err(e) => return Err(self.failed(scope, plan, e).await),
        };
        self.meter(scope, plan, purpose, &req.model, &turn.usage)
            .await?;
        Ok(turn)
    }

    /// Credits still left right before a provider call (plan() checked once per turn, and
    /// concurrent turns spend the same credits): the period quota plus top-ups on OpsAgent's
    /// key, the monthly ceiling on BYOK. Overshoot is then one call per concurrent request.
    async fn recheck(&self, org: Uuid, plan: &CallPlan) -> Result<(), AiCallError> {
        let ai = self.uow.ai();
        let left = match plan.key_id {
            Some(_) => {
                let ceiling = ai.credit_ceiling(org).await?;
                let Some(c) = ceiling else {
                    return Ok(());
                };
                let (since, until) = quota_period(&OrgBilling::default(), self.clock.now());
                c - ai.credits_used(org, KeySource::Byok, since, until).await?
            }
            None => {
                let q = self.quota(&*self.uow, org).await?;
                (q.quota - q.used).max(Decimal::ZERO) + ai.topup_balance(org).await?
            }
        };
        match left > Decimal::ZERO {
            true => Ok(()),
            false => Err(AiCallError::QuotaReached),
        }
    }

    /// The call, retried after each `backoff` wait while rate limited.
    async fn attempt(
        &self,
        p: &dyn ModelProvider,
        plan: &CallPlan,
        req: &ModelRequest,
        sink: &mut dyn TextSink,
    ) -> Result<ModelTurn, ModelError> {
        let mut waits = self.s.backoff.iter();
        loop {
            match p
                .stream(
                    &self.s.official(plan.provider, &plan.api_key),
                    req,
                    &mut *sink,
                )
                .await
            {
                Err(ModelError::RateLimited) => match waits.next() {
                    Some(d) => tokio::time::sleep(*d).await,
                    None => return Err(ModelError::RateLimited),
                },
                r => return r,
            }
        }
    }
}

pub(super) fn quota_reached(detail: &str) -> AppError {
    refused(StatusCode::PAYMENT_REQUIRED, AI_QUOTA_REACHED, detail)
}
