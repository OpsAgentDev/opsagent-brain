//! Dashboard AI use cases (dashboard-ai.md): who pays and metering (`AiAccess`, the only
//! caller of a `ModelProvider`), the on/off switch, the organisation's own key (BYOK) and
//! top-ups, explanations and chat. Prompts, completions and keys are never logged or audited.
mod access;
mod byok;
mod chat;
mod explain;
mod failures;
mod fallback;
mod meter;
mod notices;
mod settings;
mod topup;

#[cfg(test)]
mod tests;

use std::{sync::Arc, time::Duration};

use axum::http::StatusCode;
use opsagent_core::{
    ai::{KeySource, ModelKey, ModelRole, Slot},
    endpoint::UrlPolicy,
    model::{AiProvider, Endpoint, ModelInfo},
};
use opsagent_secrets::{Aad, Kek};
use uuid::Uuid;
use zeroize::Zeroizing;

pub use access::{AiAccess, AiStatus, CallPlan, Conn};
pub use byok::{DeleteKey, KeyModel, KeyPatch, ListKeyModels, PatchKey, PutKey};
pub use chat::{
    wrap_tool_result, ChatEvent, ChatSessions, ChatTurn, Turn, AI_BUSY, CHAT_PROMPT_VERSION,
    CHAT_SYSTEM_PROMPT, CHAT_TOOLS,
};
pub use explain::{current_hash, ExplainFinding, EXPLAIN_PROMPT_VERSION};
pub use failures::AiCallError;
pub use notices::Notices;
pub use settings::SetEnabled;
pub use topup::StartTopup;

use crate::{
    actions::uow::Repos,
    config::{preferred_models, Config, ModelMode, OpsAgentConnection},
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
pub const AI_MODEL_INVALID: &str = "ai_model_invalid";
pub const AI_ENDPOINT_INVALID: &str = "ai_endpoint_invalid";
pub const AI_PRIMARY_REQUIRED: &str = "ai_primary_required";
pub const MODELS_REQUIRED: &str = "models_required";

pub struct Ai {
    pub access: Arc<AiAccess>,
    pub set_enabled: SetEnabled,
    pub put_key: PutKey,
    pub list_key_models: ListKeyModels,
    pub patch_key: PatchKey,
    pub delete_key: DeleteKey,
    pub topup: StartTopup,
    pub explain: ExplainFinding,
    pub chat_sessions: ChatSessions,
}

/// What the AI actions read from `Config`. No `Debug`: it holds OpsAgent's keys.
#[derive(Clone)]
pub struct AiSettings {
    /// OpsAgent's connections; `None` when unset. `OPSAGENT_MODEL_PROVIDER=fake` gives an
    /// anthropic primary with an empty key (the fake serves it).
    pub opsagent: Option<Conn>,
    pub opsagent_backup: Option<Conn>,
    /// The styles' official URLs (`ANTHROPIC_API_BASE`/`OPENAI_API_BASE` override them).
    pub anthropic_base: String,
    pub openai_base: String,
    /// `Public` for customers' URLs, `Local` when `AI_ENDPOINT_ALLOW_PRIVATE`.
    pub policy: UrlPolicy,
    pub billing_enforced: bool,
    /// Top-ups need Stripe and OpsAgent's key: credits pay only for OpsAgent's key, so
    /// with customers' own keys only there is nothing to buy.
    pub topups: bool,
    pub web_base_url: String,
    /// The waits between retries of a rate-limited call (plan ruling 15).
    pub backoff: Vec<Duration>,
}

impl AiSettings {
    pub fn new(c: &Config) -> Self {
        let m = c.model_settings();
        let fake = (m.mode == ModelMode::Fake).then(|| OpsAgentConnection::anthropic(""));
        let mut s = Self {
            opsagent: None,
            opsagent_backup: None,
            anthropic_base: m.anthropic_api_base.clone(),
            openai_base: m.openai_api_base.clone(),
            policy: if m.allow_private {
                UrlPolicy::Local
            } else {
                UrlPolicy::Public
            },
            billing_enforced: c.billing_enforced,
            topups: false,
            web_base_url: c.web_base_url.clone(),
            backoff: [1, 2, 4].map(Duration::from_secs).to_vec(),
        };
        s.opsagent = fake.or(m.opsagent).map(|o| s.conn(o, Slot::Primary));
        s.opsagent_backup = m.opsagent_backup.map(|o| s.conn(o, Slot::Backup));
        s.topups = s.opsagent.is_some() && c.stripe_configured();
        s
    }

    fn conn(&self, o: OpsAgentConnection, slot: Slot) -> Conn {
        let base_host = o
            .base_url
            .as_deref()
            .and_then(|u| reqwest::Url::parse(u).ok())
            .and_then(|u| u.host_str().map(str::to_owned));
        Conn {
            style: o.style,
            source: KeySource::OpsAgent,
            slot,
            key_id: None,
            base_url: self.base_for(o.style, o.base_url.as_deref()),
            base_host,
            custom: false,
            models: o.models,
            api_key: Zeroizing::new(o.api_key),
        }
    }

    /// `custom` when given, else `style`'s official URL.
    pub fn base_for(&self, style: AiProvider, custom: Option<&str>) -> String {
        custom.map_or_else(
            || match style {
                AiProvider::Anthropic => self.anthropic_base.clone(),
                AiProvider::OpenAi => self.openai_base.clone(),
            },
            str::to_owned,
        )
    }

    /// `style`'s official endpoint with `api_key`, on system DNS.
    fn official<'a>(&'a self, style: AiProvider, api_key: &'a str) -> Endpoint<'a> {
        let base_url = match style {
            AiProvider::Anthropic => &self.anthropic_base,
            AiProvider::OpenAi => &self.openai_base,
        };
        Endpoint {
            base_url,
            api_key,
            custom: false,
            pin: &[],
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
