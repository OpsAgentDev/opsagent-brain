//! Dashboard AI use cases (dashboard-ai.md): who pays and metering (`AiAccess`, the only
//! caller of a `ModelProvider`), the on/off switch, the organisation's own key (BYOK) and
//! top-ups. Prompts, completions and keys are never logged or audited.
mod access;
mod byok;
mod explain;
mod failures;
mod meter;
mod notices;
mod settings;
mod topup;

#[cfg(test)]
mod tests;

use std::{sync::Arc, time::Duration};

use axum::http::StatusCode;
use opsagent_core::{
    ai::{ModelKey, ModelRole},
    model::{AiProvider, ModelInfo},
};
use opsagent_secrets::{Aad, Kek};
use uuid::Uuid;
use zeroize::Zeroizing;

pub use access::{AiAccess, AiStatus, CallPlan};
pub use byok::{DeleteKey, KeyModel, KeyPatch, ListKeyModels, PatchKey, PutKey};
pub use explain::{current_hash, ExplainFinding, EXPLAIN_PROMPT_VERSION};
pub use failures::AiCallError;
pub use notices::Notices;
pub use settings::SetEnabled;
pub use topup::StartTopup;

use crate::{
    actions::uow::Repos,
    config::{preferred_models, Config, ModelMode},
    creds::Dek,
    error::{AppError, AppResult},
};

pub const AI_DISABLED: &str = "ai_disabled";
pub const AI_UNAVAILABLE: &str = "ai_unavailable";
pub const AI_KEY_FAILING: &str = "ai_key_failing";
pub const AI_QUOTA_REACHED: &str = "ai_quota_reached";
pub const AI_KEY_INVALID: &str = "ai_key_invalid";
pub const AI_PROVIDER_OUTAGE: &str = "ai_provider_outage";
pub const AI_RATE_LIMITED: &str = "ai_rate_limited";

pub struct Ai {
    pub access: Arc<AiAccess>,
    pub set_enabled: SetEnabled,
    pub put_key: PutKey,
    pub list_key_models: ListKeyModels,
    pub patch_key: PatchKey,
    pub delete_key: DeleteKey,
    pub topup: StartTopup,
    pub explain: ExplainFinding,
}

/// What the AI actions read from `Config`. No `Debug`: it holds OpsAgent's key.
#[derive(Clone)]
pub struct AiSettings {
    /// OpsAgent's Anthropic key; `None` when unset. `OPSAGENT_MODEL_PROVIDER=fake` counts as
    /// set (the fake serves as OpsAgent's key, so its empty key is fine).
    pub opsagent_key: Option<Zeroizing<String>>,
    pub billing_enforced: bool,
    /// The top-up button shows only then.
    pub stripe_configured: bool,
    pub web_base_url: String,
    /// The waits between retries of a rate-limited call (plan ruling 15).
    pub backoff: Vec<Duration>,
}

impl AiSettings {
    pub fn new(c: &Config) -> Self {
        let m = c.model_settings();
        let set = m.mode == ModelMode::Fake || !m.anthropic_api_key.is_empty();
        Self {
            opsagent_key: set.then(|| Zeroizing::new(m.anthropic_api_key.clone())),
            billing_enforced: c.billing_enforced,
            stripe_configured: c.stripe_configured(),
            web_base_url: c.web_base_url.clone(),
            backoff: [1, 2, 4].map(Duration::from_secs).to_vec(),
        }
    }

    /// `WEB_BASE_URL/settings/ai`, with `query` when not empty.
    fn settings_url(&self, query: &str) -> String {
        let base = self.web_base_url.trim_end_matches('/');
        format!("{base}/settings/ai{query}")
    }
}

pub(crate) fn refused(status: StatusCode, code: &'static str, detail: &str) -> AppError {
    AppError::Refused {
        status,
        code,
        detail: detail.into(),
    }
}

/// 422 `invalid`.
fn invalid(detail: &str) -> AppError {
    refused(StatusCode::UNPROCESSABLE_ENTITY, "invalid", detail)
}

fn key_invalid() -> AppError {
    refused(
        StatusCode::UNPROCESSABLE_ENTITY,
        AI_KEY_INVALID,
        "The provider did not accept this key.",
    )
}

fn aad(organisation_id: Uuid) -> Aad {
    Aad {
        organisation_id,
        table: "model_keys",
        column: "ciphertext",
    }
}

/// The key's plaintext, opened under the organisation's DEK.
async fn open_key(repos: &dyn Repos, kek: &dyn Kek, k: &ModelKey) -> AppResult<Zeroizing<String>> {
    let org = k.organisation_id;
    let dek = Dek::of(repos.orgs(), kek, org).await?;
    let plain = dek.open_bytes(&k.ciphertext, &k.nonce, &aad(org))?;
    String::from_utf8(plain.to_vec())
        .map(Zeroizing::new)
        .map_err(|_| AppError::Internal("model key is not UTF-8".into()))
}

/// The role's model on `role`'s BYOK key.
fn role_model(k: &ModelKey, role: ModelRole) -> &str {
    match role {
        ModelRole::Routine => &k.models.routine,
        ModelRole::Chat => &k.models.chat,
    }
}

/// The BYOK default for `role` from the key's live list: the first preferred id present,
/// else the first tool-capable model.
fn pick_default(provider: AiProvider, role: ModelRole, list: &[ModelInfo]) -> Option<String> {
    let listed = |id: &&&str| list.iter().any(|m| m.id == **id);
    preferred_models(provider, role)
        .iter()
        .find(listed)
        .map(|id| (*id).to_owned())
        .or_else(|| list.iter().find(|m| m.tools).map(|m| m.id.clone()))
}
