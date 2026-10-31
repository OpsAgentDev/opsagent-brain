//! `AiAccess`: who pays for a call (dashboard-ai.md, Who pays; ai-connections.md, Primary
//! and backup) and the quota and ceiling checks (the call: `fallback.rs`; its failures:
//! `failures.rs`; metering: `meter.rs`).
use std::sync::Arc;

use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use opsagent_core::{
    ai::{
        period_quota, quota_period, KeySource, KeyStatus, ModelKey, ModelRole, OrgKeys, RoleModels,
        Slot,
    },
    billing::OrgBilling,
    endpoint::HostResolver,
    model::AiProvider,
    repo::Clock,
};
use opsagent_secrets::Kek;
use sea_orm::prelude::Decimal;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    failures::AiCallError, host_of, notices::Notices, open_key, refused, AiSettings, AI_DISABLED,
    AI_QUOTA_REACHED,
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

/// Who pays for one call: the connection serving it and, before its first call only, the
/// same payer's backup (spec, Settled 3). No `Debug`: it holds keys.
pub struct CallPlan {
    pub conn: Conn,
    pub(super) backup: Option<Conn>,
    pub(super) role: ModelRole,
}

impl CallPlan {
    pub fn provider(&self) -> AiProvider {
        self.conn.style
    }

    /// The serving connection's model for the plan's role.
    pub fn model(&self) -> &str {
        self.conn.model(self.role)
    }

    pub fn source(&self) -> KeySource {
        self.conn.source
    }
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

impl Conn {
    pub(super) fn model(&self, role: ModelRole) -> &str {
        match role {
            ModelRole::Routine => &self.models.routine,
            ModelRole::Chat => &self.models.chat,
        }
    }
}

/// The organisation's AI state as `GET /orgs/{org}/ai` reports it.
#[derive(Debug, Clone, PartialEq)]
pub struct AiStatus {
    pub enabled: bool,
    /// `ready`, or the code a call would end with now.
    pub state: &'static str,
    /// Who would pay: BYOK when a primary is set, else OpsAgent's key when configured.
    pub source: Option<KeySource>,
    /// OpsAgent-key credits used this period.
    pub used: Decimal,
    pub quota: Decimal,
    pub topup_balance: Decimal,
    pub period: (DateTime<Utc>, DateTime<Utc>),
    /// BYOK credits this calendar month (UTC).
    pub byok_used_this_month: Decimal,
    /// A BYOK key's model is unpriced, so its credits are estimates.
    pub estimated: bool,
    pub keys: OrgKeys,
    /// Credits per calendar month (UTC) across both BYOK connections; `None` is no ceiling.
    pub ceiling: Option<Decimal>,
    pub topup_available: bool,
}

/// Everything the who-pays table and the status read, at one moment.
struct Snapshot {
    enabled: bool,
    keys: OrgKeys,
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

enum Payer<'a> {
    /// `serving` is the backup when the primary is `failing`, which `plan` tells the owners.
    Byok {
        serving: &'a ModelKey,
        backup: Option<&'a ModelKey>,
    },
    OpsAgent,
}

pub struct AiAccess {
    pub(super) uow: Arc<dyn UnitOfWork>,
    pub(super) kek: Arc<dyn Kek>,
    pub(super) models: ModelProviders,
    pub(super) resolver: Arc<dyn HostResolver>,
    pub(super) notices: Notices,
    pub(super) clock: Arc<dyn Clock>,
    pub(super) s: AiSettings,
}

impl AiAccess {
    pub fn new(
        uow: Arc<dyn UnitOfWork>,
        kek: Arc<dyn Kek>,
        models: ModelProviders,
        resolver: Arc<dyn HostResolver>,
        notices: Notices,
        clock: Arc<dyn Clock>,
        s: AiSettings,
    ) -> Self {
        Self {
            uow,
            kek,
            models,
            resolver,
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
            Payer::Byok { serving, backup } => {
                let backup = match backup {
                    Some(b) => Some(self.byok_conn(b).await?),
                    None => None,
                };
                CallPlan {
                    conn: self.byok_conn(serving).await?,
                    backup,
                    role,
                }
            }
            Payer::OpsAgent => CallPlan {
                conn: self.s.opsagent.clone().ok_or(AiCallError::Unavailable)?,
                backup: self.s.opsagent_backup.clone(),
                role,
            },
        })
    }

    /// `k` as a connection, its key opened.
    pub(super) async fn byok_conn(&self, k: &ModelKey) -> AppResult<Conn> {
        let base_host = k.base_url.as_deref().and_then(host_of);
        Ok(Conn {
            style: k.provider,
            source: KeySource::Byok,
            slot: k.slot,
            key_id: Some(k.id),
            base_url: self.s.base_for(k.provider, k.base_url.as_deref()),
            base_host,
            custom: k.base_url.is_some(),
            models: k.models.clone(),
            api_key: open_key(&*self.uow, &*self.kek, k).await?,
        })
    }

    pub async fn status(&self, scope: &OrgScope) -> AppResult<AiStatus> {
        let snap = self.snapshot(scope.organisation.id).await?;
        let state = match self.payer(&snap) {
            Ok(_) => "ready",
            Err(AppError::Refused { code, .. }) => code,
            Err(e) => return Err(e),
        };
        let source = match (&snap.keys.primary, &self.s.opsagent) {
            (Some(_), _) => Some(KeySource::Byok),
            (None, Some(_)) => Some(KeySource::OpsAgent),
            (None, None) => None,
        };
        let keys = [&snap.keys.primary, &snap.keys.backup];
        let estimated = keys.iter().filter_map(|k| k.as_ref()).any(|k| {
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
            keys: snap.keys,
            ceiling: snap.ceiling,
            topup_available: self.s.topups,
        })
    }

    async fn snapshot(&self, org: Uuid) -> AppResult<Snapshot> {
        let ai = self.uow.ai();
        let (since, until) = quota_period(&OrgBilling::default(), self.clock.now());
        Ok(Snapshot {
            enabled: ai.enabled(org).await?,
            keys: ai.keys(org).await?,
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
    fn payer<'a>(&self, snap: &'a Snapshot) -> AppResult<Payer<'a>> {
        if !snap.enabled {
            let detail = "Dashboard AI is off for this organisation.";
            return Err(refused(StatusCode::CONFLICT, AI_DISABLED, detail));
        }
        if let Some(p) = &snap.keys.primary {
            if snap.ceiling.is_some_and(|c| snap.byok_month >= c) {
                return Err(quota_reached("Your monthly credit ceiling is reached."));
            }
            // An outage key is still tried: its next success clears it.
            let usable = |k: &&ModelKey| k.status != KeyStatus::Failing;
            let backup = snap.keys.backup.as_ref().filter(usable);
            return match (p.status == KeyStatus::Failing, backup) {
                (false, backup) => Ok(Payer::Byok { serving: p, backup }),
                (true, Some(b)) => Ok(Payer::Byok {
                    serving: b,
                    backup: None,
                }),
                (true, None) => Err(AiCallError::KeyFailing.into()),
            };
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
}

pub(super) fn quota_reached(detail: &str) -> AppError {
    refused(StatusCode::PAYMENT_REQUIRED, AI_QUOTA_REACHED, detail)
}
