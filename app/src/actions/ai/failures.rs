//! How a failed model call ends: the error the caller gets, and a BYOK key's status and
//! owner emails (dashboard-ai.md, The model port; plan rulings 3 and 4).
use axum::http::StatusCode;
use chrono::Duration;
use opsagent_core::{
    ai::{KeySource, KeyStatus, ModelKey, ModelRole, OrgKeys, Slot},
    model::{AiProvider, ModelError},
    repo::RepoError,
};
use uuid::Uuid;

use super::{
    access::{AiAccess, CallPlan},
    notices::Notice,
    pick_default, refused, AI_KEY_FAILING, AI_MODEL_INVALID, AI_PROVIDER_OUTAGE, AI_QUOTA_REACHED,
    AI_RATE_LIMITED, AI_UNAVAILABLE,
};
use crate::{actions::orgs::OrgScope, error::AppError};

/// A BYOK key still in `provider_outage` this long after `status_since` gets one email.
const OUTAGE_NOTICE_HOURS: i64 = 2;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AiCallError {
    #[error("ai_rate_limited")]
    RateLimited,
    #[error("ai_key_failing")]
    KeyFailing,
    #[error("ai_provider_outage")]
    Outage,
    #[error("ai_unavailable")]
    Unavailable,
    /// The credits ran out between `plan` and this call.
    #[error("ai_quota_reached")]
    QuotaReached,
    /// A BYOK model is gone and its endpoint offers no replacement.
    #[error("ai_model_invalid")]
    ModelInvalid,
    #[error("internal: {0}")]
    Internal(String),
}

impl AiCallError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::RateLimited => AI_RATE_LIMITED,
            Self::KeyFailing => AI_KEY_FAILING,
            Self::Outage => AI_PROVIDER_OUTAGE,
            Self::Unavailable => AI_UNAVAILABLE,
            Self::QuotaReached => AI_QUOTA_REACHED,
            Self::ModelInvalid => AI_MODEL_INVALID,
            Self::Internal(_) => "internal",
        }
    }
}

impl From<AiCallError> for AppError {
    fn from(e: AiCallError) -> Self {
        let (status, detail) = match e {
            AiCallError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                "The model provider is busy; try again in a minute.",
            ),
            AiCallError::KeyFailing => (
                StatusCode::BAD_GATEWAY,
                "Your organisation's model key was refused by its provider.",
            ),
            AiCallError::Outage => (
                StatusCode::BAD_GATEWAY,
                "Your organisation's model provider is not answering.",
            ),
            AiCallError::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Dashboard AI is not available right now.",
            ),
            AiCallError::QuotaReached => (
                StatusCode::PAYMENT_REQUIRED,
                "This organisation's AI credits are used up.",
            ),
            AiCallError::ModelInvalid => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "Your organisation's AI model is not available on its endpoint.",
            ),
            AiCallError::Internal(s) => return AppError::Internal(s),
        };
        refused(status, e.code(), detail)
    }
}

impl From<AppError> for AiCallError {
    fn from(e: AppError) -> Self {
        Self::Internal(e.to_string())
    }
}

impl From<RepoError> for AiCallError {
    fn from(e: RepoError) -> Self {
        Self::Internal(e.to_string())
    }
}

impl AiAccess {
    /// The error a failed call on `plan.conn` ends with; a BYOK key's status follows the
    /// failure. `backup_next`: the payer's backup is tried next, so OpsAgent's key logs a warning.
    pub(super) async fn failed(
        &self,
        scope: &OrgScope,
        plan: &CallPlan,
        e: ModelError,
        backup_next: bool,
    ) -> AiCallError {
        let c = &plan.conn;
        let (Some(key_id), KeySource::Byok) = (c.key_id, c.source) else {
            let code = model_code(&e);
            let (slot, model) = (c.slot.as_str(), plan.model());
            if backup_next {
                tracing::warn!(error_code = %code, slot, model, "opsagent model key call failed");
            } else {
                tracing::error!(error_code = %code, slot, model, "opsagent model key call failed");
            }
            return match e {
                ModelError::RateLimited => AiCallError::RateLimited,
                _ => AiCallError::Unavailable,
            };
        };
        let org = scope.organisation.id;
        let (r, err) = match e {
            ModelError::RateLimited => (Ok(()), AiCallError::RateLimited),
            ModelError::ModelGone => (Ok(()), AiCallError::ModelInvalid),
            ModelError::Auth => (self.key_failing(org, key_id).await, AiCallError::KeyFailing),
            ModelError::Outage => (self.outage(org, key_id).await, AiCallError::Outage),
            e => (Ok(()), AiCallError::Internal(model_code(&e))),
        };
        // The backup failed with the primary failing: Dashboard AI has stopped.
        let r = match (r, c.slot) {
            (Ok(()), Slot::Backup) => self.stopped_if_primary_failing(org).await,
            (r, _) => r,
        };
        if let Err(x) = r {
            // The key's failure is what the caller needs; the bookkeeping error is logged.
            tracing::warn!(error_code = x.code(), "ai key status update failed");
        }
        err
    }

    async fn stopped_if_primary_failing(&self, org: Uuid) -> Result<(), AiCallError> {
        match self.uow.ai().keys(org).await?.primary {
            Some(p) if p.status == KeyStatus::Failing => self.stopped(org, &p).await,
            _ => Ok(()),
        }
    }

    /// "Has stopped", once per failure of `k` (its `status_since`).
    async fn stopped(&self, org: Uuid, k: &ModelKey) -> Result<(), AiCallError> {
        let n = Notice {
            subject: "Your OpsAgent AI key is failing".into(),
            text: format!(
                "Your {} key ending {} was refused by the provider, so Dashboard AI has \
                 stopped. Replace the key, or remove it to use OpsAgent's: {}",
                provider_name(k.provider),
                k.last4,
                self.s.settings_url("")
            ),
        };
        let key = format!("failing:{}:{}", k.id, k.status_since.timestamp());
        Ok(self.notices.once(org, &key, n).await?)
    }

    /// Marks the key `failing`; the owners hear of it on the transition only. A primary with
    /// a usable backup is told when the backup serves (`backup_notice`, ruling 10) or fails
    /// (`failed`: "has stopped"); a backup failing beside a working primary, or a primary with
    /// no usable backup: the same "has stopped" email.
    async fn key_failing(&self, org: Uuid, key_id: Uuid) -> Result<(), AiCallError> {
        let now = self.clock.now();
        let ai = self.uow.ai();
        if !ai
            .set_key_status(org, key_id, KeyStatus::Failing, now)
            .await?
        {
            return Ok(());
        }
        let keys = ai.keys(org).await?;
        let Some(k) = by_id(&keys, key_id) else {
            return Ok(());
        };
        let backup_ok = keys
            .backup
            .as_ref()
            .is_some_and(|b| b.status != KeyStatus::Failing);
        let primary_ok = keys
            .primary
            .as_ref()
            .is_some_and(|p| p.status != KeyStatus::Failing);
        match k.slot {
            Slot::Primary if backup_ok => return Ok(()),
            // With the primary failing, `failed` tells the owners for the primary.
            Slot::Backup if !primary_ok => return Ok(()),
            Slot::Backup | Slot::Primary => {}
        }
        self.stopped(org, &k).await
    }

    /// Tells the owners, once per failure of the primary, that the backup is serving.
    pub(super) async fn backup_notice(&self, org: Uuid) -> crate::error::AppResult<()> {
        let keys = self.uow.ai().keys(org).await?;
        let (Some(p), Some(b)) = (keys.primary, keys.backup) else {
            return Ok(());
        };
        if p.status != KeyStatus::Failing {
            return Ok(());
        }
        let n = Notice {
            subject: "Your OpsAgent AI backup key is in use".into(),
            text: format!(
                "Your {} key ending {} was refused, so Dashboard AI is using your backup key \
                 ending {}. Replace the primary key: {}",
                provider_name(p.provider),
                p.last4,
                b.last4,
                self.s.settings_url("")
            ),
        };
        let key = format!("backup_in_use:{}:{}", p.id, p.status_since.timestamp());
        self.notices.once(org, &key, n).await
    }

    /// Marks the key `provider_outage`; a key still out `OUTAGE_NOTICE_HOURS` after it
    /// started gets one email (plan ruling 4).
    async fn outage(&self, org: Uuid, key_id: Uuid) -> Result<(), AiCallError> {
        let now = self.clock.now();
        let ai = self.uow.ai();
        // A refused key stays refused: an outage arriving late never re-enables it.
        let current = by_id(&ai.keys(org).await?, key_id);
        if current.is_none_or(|k| k.status == KeyStatus::Failing) {
            return Ok(());
        }
        if ai
            .set_key_status(org, key_id, KeyStatus::ProviderOutage, now)
            .await?
        {
            return Ok(());
        }
        let Some(k) = by_id(&ai.keys(org).await?, key_id) else {
            return Ok(());
        };
        let long = now - k.status_since >= Duration::hours(OUTAGE_NOTICE_HOURS);
        if k.status != KeyStatus::ProviderOutage || !long {
            return Ok(());
        }
        let n = Notice {
            subject: "Your AI provider has been down for 2 hours".into(),
            text: format!(
                "{} has not answered Dashboard AI calls on your key ending {} for over \
                 {OUTAGE_NOTICE_HOURS} hours. Check the provider's status page, or manage \
                 your key: {}",
                provider_name(k.provider),
                k.last4,
                self.s.settings_url("")
            ),
        };
        let key = format!("outage:{key_id}:{}", k.status_since.timestamp());
        self.notices.once(org, &key, n).await?;
        Ok(())
    }

    /// The role's default from the connection's live list, saved to its key and the plan in
    /// place of the model that is gone; the owners hear of it once (plan ruling 3). `None`
    /// when the list is unusable (plan ruling 4) or offers nothing else.
    pub(super) async fn replace_model(
        &self,
        scope: &OrgScope,
        plan: &mut CallPlan,
    ) -> Result<Option<String>, AiCallError> {
        let org = scope.organisation.id;
        let c = &plan.conn;
        let Ok(pin) = self.pinned(c).await else {
            return Ok(None);
        };
        let p = self.models.get(c.style);
        let list = match p.list_models(&Self::endpoint(c, &pin)).await {
            Ok(l) if !l.is_empty() => l,
            _ => return Ok(None),
        };
        let gone = plan.model().to_owned();
        let Some(default) = pick_default(c.style, plan.role, &list).filter(|d| *d != gone) else {
            return Ok(None);
        };
        let ai = self.uow.ai();
        let keys = ai.keys(org).await?;
        let Some(k) = c.key_id.and_then(|id| by_id(&keys, id)) else {
            return Ok(None);
        };
        let mut models = k.models.clone();
        match plan.role {
            ModelRole::Routine => models.routine = default.clone(),
            ModelRole::Chat => models.chat = default.clone(),
        }
        ai.update_key_models(org, k.slot, &models).await?;
        plan.conn.models = models;
        let n = Notice {
            subject: "OpsAgent replaced a model on your AI key".into(),
            text: format!(
                "{} no longer offers {} on your key ending {}, so Dashboard AI now uses {} \
                 for {} work. Pick another model: {}",
                provider_name(k.provider),
                gone,
                k.last4,
                default,
                plan.role.as_str(),
                self.s.settings_url("")
            ),
        };
        let key = format!("model_gone:{}:{}", k.id, gone);
        self.notices.once(org, &key, n).await?;
        Ok(Some(default))
    }
}

/// The organisation's key with `id`, in either slot.
fn by_id(keys: &OrgKeys, id: Uuid) -> Option<ModelKey> {
    [&keys.primary, &keys.backup]
        .into_iter()
        .flatten()
        .find(|k| k.id == id)
        .cloned()
}

pub(super) fn provider_name(p: AiProvider) -> &'static str {
    match p {
        AiProvider::Anthropic => "Anthropic",
        AiProvider::OpenAi => "OpenAI",
    }
}

/// The stable code of a model error (never provider text).
fn model_code(e: &ModelError) -> String {
    match e {
        ModelError::Other(c) => c.clone(),
        e => e.to_string(),
    }
}
