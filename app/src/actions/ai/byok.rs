//! The organisation's own provider key (dashboard-ai.md, BYOK; plan ruling 11): saved once
//! after a models-list check, then its models and ceiling are edited. Owner only; the
//! callers check. The key is never logged or audited, only its provider and last 4.
use std::sync::Arc;

use axum::http::StatusCode;
use opsagent_core::{
    ai::{KeyStatus, ModelKey, ModelRole, NewModelKey, RoleModels},
    audit::AuditEntry,
    model::{AiProvider, ModelError, ModelInfo},
};
use sea_orm::prelude::Decimal;
use serde_json::json;
use zeroize::Zeroizing;

use super::{
    aad, invalid, key_invalid, open_key, pick_default, refused, AiAccess, AiStatus, AI_KEY_FAILING,
    AI_PROVIDER_OUTAGE,
};
use crate::{
    actions::orgs::OrgScope,
    creds::Dek,
    error::{AppError, AppResult},
};

/// Shortest key we accept; real ones are far longer.
const MIN_KEY_LEN: usize = 20;

/// The key looks like one of `provider`'s: its prefix, ASCII letters, digits, `-` and `_`.
fn well_formed(provider: AiProvider, key: &str) -> bool {
    let prefix = match provider {
        AiProvider::Anthropic => "sk-ant-",
        AiProvider::OpenAi => "sk-",
    };
    key.starts_with(prefix)
        && key.len() >= MIN_KEY_LEN
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn provider_down() -> AppError {
    let detail = "The model provider could not be reached; try again.";
    refused(StatusCode::BAD_GATEWAY, AI_PROVIDER_OUTAGE, detail)
}

/// Saves the key (replacing any other) with the provider's default models, after its
/// models list answers. 422 `ai_key_invalid` for a malformed key (no call) or one the
/// provider refuses. Audited `ai.key.set` with the provider and last 4 only.
pub struct PutKey {
    access: Arc<AiAccess>,
}

impl PutKey {
    pub fn new(access: Arc<AiAccess>) -> Self {
        Self { access }
    }

    pub async fn run(&self, scope: &OrgScope, provider: &str, key: &str) -> AppResult<AiStatus> {
        let provider = AiProvider::parse(provider).ok_or_else(|| invalid("unknown provider"))?;
        if !well_formed(provider, key) {
            return Err(key_invalid());
        }
        let a = &self.access;
        let list = match a.models.get(provider).list_models(key).await {
            Ok(l) => l,
            Err(ModelError::Auth) => return Err(key_invalid()),
            Err(_) => return Err(provider_down()),
        };
        let pick = |role| pick_default(provider, role, &list).ok_or_else(key_invalid);
        let models = RoleModels {
            routine: pick(ModelRole::Routine)?,
            chat: pick(ModelRole::Chat)?,
        };
        let org = scope.organisation.id;
        let dek = Dek::of(a.uow.orgs(), &*a.kek, org).await?;
        let sealed = dek.seal_bytes(key.as_bytes(), &aad(org));
        let last4: String = key.chars().skip(key.chars().count() - 4).collect();
        let new = NewModelKey {
            provider,
            last4: last4.clone(),
            models,
            monthly_credit_ceiling: None,
            ciphertext: sealed.ciphertext,
            nonce: sealed.nonce.to_vec(),
            kek_version: dek.version,
        };
        let tx = a.uow.begin().await?;
        let k = tx.ai().put_key(org, &new).await?;
        let entry = AuditEntry::member(Some(org), scope.member.user_id, "ai.key.set", None)
            .with_meta(json!({ "provider": provider.as_str(), "last4": last4 }));
        let target = AuditEntry {
            target: Some(("model_key", k.id.to_string())),
            ..entry
        };
        tx.audit().record(target).await?;
        tx.commit().await?;
        a.status(scope).await
    }
}

/// One model on the key's live list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyModel {
    pub id: String,
    pub tools: bool,
    /// The role the picker preselects it for.
    pub default_for: Option<ModelRole>,
}

/// The organisation's key and its live models list (404 without a key). A list that
/// answers clears a failing key; a refused one marks it failing (502 `ai_key_failing`).
async fn live_models(a: &AiAccess, org: uuid::Uuid) -> AppResult<(ModelKey, Vec<ModelInfo>)> {
    let k = a.uow.ai().key(org).await?.ok_or(AppError::NotFound)?;
    let api_key: Zeroizing<String> = open_key(&*a.uow, &*a.kek, &k).await?;
    let now = a.clock.now();
    match a.models.get(k.provider).list_models(&api_key).await {
        Ok(list) => {
            a.uow
                .ai()
                .set_key_status(org, k.id, KeyStatus::Ok, now)
                .await?;
            Ok((k, list))
        }
        Err(ModelError::Auth) => {
            a.uow
                .ai()
                .set_key_status(org, k.id, KeyStatus::Failing, now)
                .await?;
            let detail = "The provider refused your organisation's key.";
            Err(refused(StatusCode::BAD_GATEWAY, AI_KEY_FAILING, detail))
        }
        Err(_) => Err(provider_down()),
    }
}

pub struct ListKeyModels {
    access: Arc<AiAccess>,
}

impl ListKeyModels {
    pub fn new(access: Arc<AiAccess>) -> Self {
        Self { access }
    }

    pub async fn run(&self, scope: &OrgScope) -> AppResult<Vec<KeyModel>> {
        let (k, list) = live_models(&self.access, scope.organisation.id).await?;
        let defaults = ModelRole::ALL
            .iter()
            .map(|r| (*r, pick_default(k.provider, *r, &list)))
            .collect::<Vec<_>>();
        Ok(list
            .into_iter()
            .map(|m| KeyModel {
                default_for: defaults
                    .iter()
                    .find(|(_, d)| d.as_deref() == Some(m.id.as_str()))
                    .map(|(r, _)| *r),
                id: m.id,
                tools: m.tools,
            })
            .collect())
    }
}

/// What `PATCH /ai/key` changes; `None` keeps the stored value.
#[derive(Debug, Clone, Default)]
pub struct KeyPatch {
    pub models: Option<RoleModels>,
    /// `Some(None)` removes the ceiling.
    pub ceiling: Option<Option<Decimal>>,
}

/// Edits the key's models (each on its live list; chat's must call tools, else 422
/// `invalid`) and its monthly credit ceiling (not negative).
pub struct PatchKey {
    access: Arc<AiAccess>,
}

impl PatchKey {
    pub fn new(access: Arc<AiAccess>) -> Self {
        Self { access }
    }

    pub async fn run(&self, scope: &OrgScope, p: KeyPatch) -> AppResult<AiStatus> {
        let a = &self.access;
        let org = scope.organisation.id;
        if p.ceiling.flatten().is_some_and(|c| c < Decimal::ZERO) {
            return Err(invalid("monthly_credit_ceiling must not be negative"));
        }
        let k = a.uow.ai().key(org).await?.ok_or(AppError::NotFound)?;
        if let Some(m) = &p.models {
            let (_, list) = live_models(a, org).await?;
            let find = |id: &str| list.iter().find(|i| i.id == id);
            if find(&m.routine).is_none() {
                return Err(invalid("routine model is not on the key's models list"));
            }
            match find(&m.chat) {
                None => return Err(invalid("chat model is not on the key's models list")),
                Some(i) if !i.tools => return Err(invalid("chat model cannot call tools")),
                Some(_) => {}
            }
        }
        let models = p.models.unwrap_or(k.models);
        let ceiling = p.ceiling.unwrap_or(k.monthly_credit_ceiling);
        a.uow.ai().update_key(org, &models, ceiling).await?;
        a.status(scope).await
    }
}

/// Deletes the key (404 without one): the organisation returns to OpsAgent's key. Audited
/// `ai.key.delete`.
pub struct DeleteKey {
    access: Arc<AiAccess>,
}

impl DeleteKey {
    pub fn new(access: Arc<AiAccess>) -> Self {
        Self { access }
    }

    pub async fn run(&self, scope: &OrgScope) -> AppResult<()> {
        let org = scope.organisation.id;
        let tx = self.access.uow.begin().await?;
        if !tx.ai().delete_key(org).await? {
            return Err(AppError::NotFound);
        }
        let entry = AuditEntry::member(Some(org), scope.member.user_id, "ai.key.delete", None);
        tx.audit().record(entry).await?;
        tx.commit().await?;
        Ok(())
    }
}
