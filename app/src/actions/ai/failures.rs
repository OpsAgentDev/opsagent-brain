//! How a failed model call ends: the error the caller gets, and a BYOK key's status and
//! owner emails (dashboard-ai.md, The model port; plan rulings 3 and 4).
use axum::http::StatusCode;
use chrono::Duration;
use opsagent_core::{
    ai::{KeySource, KeyStatus, ModelRole},
    model::{AiProvider, ModelError, ModelProvider},
    repo::RepoError,
};
use uuid::Uuid;

use super::{
    access::{AiAccess, CallPlan},
    notices::Notice,
    pick_default, refused, AI_KEY_FAILING, AI_PROVIDER_OUTAGE, AI_QUOTA_REACHED, AI_RATE_LIMITED,
    AI_UNAVAILABLE,
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
    /// The error a failed call ends with; a BYOK key's status follows the failure.
    pub(super) async fn failed(
        &self,
        scope: &OrgScope,
        plan: &CallPlan,
        e: ModelError,
    ) -> AiCallError {
        let (Some(key_id), KeySource::Byok) = (plan.key_id, plan.source) else {
            let code = model_code(&e);
            tracing::error!(error_code = %code, model = %plan.model, "opsagent model key call failed");
            return match e {
                ModelError::RateLimited => AiCallError::RateLimited,
                _ => AiCallError::Unavailable,
            };
        };
        let org = scope.organisation.id;
        let (r, err) = match e {
            ModelError::RateLimited => return AiCallError::RateLimited,
            ModelError::Auth => (self.key_failing(org, key_id).await, AiCallError::KeyFailing),
            ModelError::Outage => (self.outage(org, key_id).await, AiCallError::Outage),
            e => return AiCallError::Internal(model_code(&e)),
        };
        if let Err(x) = r {
            // The key's failure is what the caller needs; the bookkeeping error is logged.
            tracing::warn!(error_code = x.code(), "ai key status update failed");
        }
        err
    }

    /// Marks the key `failing`; the owners hear of it on the transition only.
    async fn key_failing(&self, org: Uuid, key_id: Uuid) -> Result<(), AiCallError> {
        let now = self.clock.now();
        let ai = self.uow.ai();
        if !ai
            .set_key_status(org, key_id, KeyStatus::Failing, now)
            .await?
        {
            return Ok(());
        }
        let Some(k) = ai.key(org).await? else {
            return Ok(());
        };
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
        self.notices
            .tell(org, &format!("failing:{key_id}"), n)
            .await?;
        Ok(())
    }

    /// Marks the key `provider_outage`; a key still out `OUTAGE_NOTICE_HOURS` after it
    /// started gets one email (plan ruling 4).
    async fn outage(&self, org: Uuid, key_id: Uuid) -> Result<(), AiCallError> {
        let now = self.clock.now();
        let ai = self.uow.ai();
        // A refused key stays refused: an outage arriving late never re-enables it.
        let current = ai.key(org).await?.filter(|k| k.id == key_id);
        if current.is_none_or(|k| k.status == KeyStatus::Failing) {
            return Ok(());
        }
        if ai
            .set_key_status(org, key_id, KeyStatus::ProviderOutage, now)
            .await?
        {
            return Ok(());
        }
        let Some(k) = ai.key(org).await?.filter(|k| k.id == key_id) else {
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

    /// The role's default from the key's live list, saved to the key in place of the model
    /// that is gone; the owners hear of it once (plan ruling 3).
    pub(super) async fn replace_model(
        &self,
        scope: &OrgScope,
        plan: &CallPlan,
        p: &dyn ModelProvider,
    ) -> Result<String, AiCallError> {
        let org = scope.organisation.id;
        let list = match p.list_models(&plan.api_key).await {
            Ok(l) => l,
            Err(e) => return Err(self.failed(scope, plan, e).await),
        };
        let gone = || AiCallError::Internal("model_gone".into());
        let default = pick_default(plan.provider, plan.role, &list)
            .filter(|d| *d != plan.model)
            .ok_or_else(gone)?;
        let ai = self.uow.ai();
        let k = ai.key(org).await?.filter(|k| Some(k.id) == plan.key_id);
        let k = k.ok_or_else(gone)?;
        let mut models = k.models.clone();
        match plan.role {
            ModelRole::Routine => models.routine = default.clone(),
            ModelRole::Chat => models.chat = default.clone(),
        }
        ai.update_key(org, &models, k.monthly_credit_ceiling)
            .await?;
        let n = Notice {
            subject: "OpsAgent replaced a model on your AI key".into(),
            text: format!(
                "{} no longer offers {} on your key ending {}, so Dashboard AI now uses {} \
                 for {} work. Pick another model: {}",
                provider_name(k.provider),
                plan.model,
                k.last4,
                default,
                plan.role.as_str(),
                self.s.settings_url("")
            ),
        };
        let key = format!("model_gone:{}:{}", k.id, plan.model);
        self.notices.once(org, &key, n).await?;
        Ok(default)
    }
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
