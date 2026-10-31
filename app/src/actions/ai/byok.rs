//! The organisation's own connections (dashboard-ai.md, BYOK; ai-connections.md, Choosing
//! models; plan rulings 4-6, 12, 13): one per slot, saved after its models list or a
//! 1-token check answers. Owner only; the callers check. Keys and full URLs are never
//! logged or audited, only the style, last 4 and host.
use std::{net::SocketAddr, sync::Arc};

use axum::http::StatusCode;
use opsagent_core::{
    ai::{KeyStatus, ModelRole, NewModelKey, RoleModels, Slot},
    audit::AuditEntry,
    endpoint::{check_url, pin, CheckedUrl, EndpointRefusal},
    model::{
        AiProvider, Endpoint, ModelError, ModelInfo, ModelMessage, ModelRequest, MsgRole, Part,
    },
};
use serde_json::json;

use super::{
    aad, explain::NoSink, failures::AiCallError, host_of, invalid, key_invalid, pick_default,
    refused, AiAccess, AiStatus, Conn, AI_ENDPOINT_INVALID, AI_KEY_FAILING, AI_PRIMARY_REQUIRED,
    AI_PROVIDER_OUTAGE, MODELS_REQUIRED,
};
use crate::{
    actions::orgs::OrgScope,
    creds::Dek,
    error::{AppError, AppResult},
};

/// Shortest official key we accept; real ones are far longer.
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

/// `s` is `len` printable ASCII characters with no spaces (ruling 6).
fn graphic(s: &str, len: std::ops::RangeInclusive<usize>) -> bool {
    len.contains(&s.len()) && s.bytes().all(|b| b.is_ascii_graphic())
}

fn provider_down() -> AppError {
    let detail = "The model provider could not be reached; try again.";
    refused(StatusCode::BAD_GATEWAY, AI_PROVIDER_OUTAGE, detail)
}

/// A list naming at least one model; `None` when the endpoint offers none (ruling 4).
fn usable(r: Result<Vec<ModelInfo>, ModelError>) -> Result<Option<Vec<ModelInfo>>, ModelError> {
    match r {
        Ok(l) if !l.is_empty() => Ok(Some(l)),
        Ok(_) | Err(ModelError::ModelGone | ModelError::Other(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// `m` on the live `list` (chat's must call tools), or, typed with no list, by shape.
fn check_models(m: &RoleModels, list: Option<&[ModelInfo]>) -> AppResult<()> {
    let Some(list) = list else {
        return match graphic(&m.routine, 1..=200) && graphic(&m.chat, 1..=200) {
            true => Ok(()),
            false => Err(invalid(
                "A model id is 1 to 200 printable characters with no spaces.",
            )),
        };
    };
    let find = |id: &str| list.iter().find(|i| i.id == id);
    if find(&m.routine).is_none() {
        return Err(invalid("routine model is not on the key's models list"));
    }
    match find(&m.chat) {
        None => Err(invalid("chat model is not on the key's models list")),
        Some(i) if !i.tools => Err(invalid("chat model cannot call tools")),
        Some(_) => Ok(()),
    }
}

/// The ruling-5 check of a typed chat model: one unmetered 1-token call.
async fn one_token(
    a: &AiAccess,
    style: AiProvider,
    ep: &Endpoint<'_>,
    chat: &str,
) -> AppResult<()> {
    let req = ModelRequest {
        model: chat.into(),
        system: "Reply with OK.".into(),
        messages: vec![ModelMessage {
            role: MsgRole::User,
            parts: vec![Part::Text("OK".into())],
        }],
        tools: vec![],
        max_tokens: 1,
    };
    match a.models.get(style).stream(ep, &req, &mut NoSink).await {
        Ok(_) => Ok(()),
        Err(ModelError::Auth) => Err(key_invalid()),
        Err(ModelError::ModelGone | ModelError::Other(_)) => Err(AiCallError::ModelInvalid.into()),
        Err(ModelError::Outage | ModelError::RateLimited) => Err(provider_down()),
    }
}

/// `raw` judged under the settings' policy, and the addresses it may connect to.
async fn check_endpoint(a: &AiAccess, raw: &str) -> AppResult<(CheckedUrl, Vec<SocketAddr>)> {
    let bad = |r: EndpointRefusal| {
        refused(
            StatusCode::UNPROCESSABLE_ENTITY,
            AI_ENDPOINT_INVALID,
            r.reason(),
        )
    };
    let u = check_url(raw, a.s.policy).map_err(bad)?;
    let addrs = pin(&*a.resolver, &u, a.s.policy).await.map_err(bad)?;
    Ok((u, addrs))
}

/// What `PUT /orgs/{org}/ai/keys/{slot}` sends.
pub struct KeyInput {
    pub style: String,
    /// Empty or `None` is the style's official URL.
    pub base_url: Option<String>,
    pub api_key: String,
    /// `None` takes the defaults from the live list.
    pub models: Option<RoleModels>,
}

#[derive(Debug)]
pub struct PutKeyOutcome {
    pub status: AiStatus,
    /// The live list; empty when the owner typed the model ids.
    pub models: Vec<KeyModel>,
}

/// Saves the slot's connection (replacing it) once its endpoint, key shape and models
/// pass, in the brief's order. Audited `ai.key.set` with the style, slot, host and last 4.
pub struct PutKey {
    access: Arc<AiAccess>,
}

impl PutKey {
    pub fn new(access: Arc<AiAccess>) -> Self {
        Self { access }
    }

    pub async fn run(
        &self,
        scope: &OrgScope,
        slot: Slot,
        input: KeyInput,
    ) -> AppResult<PutKeyOutcome> {
        let a = &*self.access;
        let style = AiProvider::parse(&input.style).ok_or_else(|| invalid("unknown style"))?;
        let org = scope.organisation.id;
        if slot == Slot::Backup && a.uow.ai().keys(org).await?.primary.is_none() {
            let detail = "Save a primary key first.";
            return Err(refused(StatusCode::CONFLICT, AI_PRIMARY_REQUIRED, detail));
        }
        let custom = match input.base_url.as_deref().map(str::trim) {
            None | Some("") => None,
            Some(u) => Some(check_endpoint(a, u).await?),
        };
        let key = input.api_key.as_str();
        let shaped = match custom {
            None => well_formed(style, key),
            Some(_) => graphic(key, 8..=512),
        };
        if !shaped {
            return Err(key_invalid());
        }
        let ep = match &custom {
            Some((u, addrs)) => Endpoint {
                base_url: &u.base,
                api_key: key,
                custom: true,
                pin: addrs,
            },
            None => a.s.official(style, key),
        };
        let list = match usable(a.models.get(style).list_models(&ep).await) {
            Ok(l) => l,
            Err(ModelError::Auth) => return Err(key_invalid()),
            Err(_) => return Err(provider_down()),
        };
        let models = match (list.as_deref(), input.models) {
            (Some(l), Some(m)) => check_models(&m, Some(l)).map(|()| m)?,
            (Some(l), None) => {
                let pick = |role| pick_default(style, role, l).ok_or_else(key_invalid);
                RoleModels {
                    routine: pick(ModelRole::Routine)?,
                    chat: pick(ModelRole::Chat)?,
                }
            }
            (None, _) if custom.is_none() => return Err(key_invalid()),
            (None, None) => {
                let detail =
                    "This endpoint has no models list; type the routine and chat model ids.";
                return Err(refused(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    MODELS_REQUIRED,
                    detail,
                ));
            }
            (None, Some(m)) => {
                check_models(&m, None)?;
                one_token(a, style, &ep, &m.chat).await?;
                m
            }
        };
        let (base_url, base_host) = custom.map(|(u, _)| (u.base, u.host)).unzip();
        let dek = Dek::of(a.uow.orgs(), &*a.kek, org).await?;
        let sealed = dek.seal_bytes(key.as_bytes(), &aad(org));
        let last4: String = key.chars().skip(key.chars().count() - 4).collect();
        let new = NewModelKey {
            provider: style,
            last4: last4.clone(),
            models,
            slot,
            base_url,
            ciphertext: sealed.ciphertext,
            nonce: sealed.nonce.to_vec(),
            kek_version: dek.version,
        };
        let tx = a.uow.begin().await?;
        let k = tx.ai().put_key(org, &new).await?;
        let meta = json!({ "provider": style.as_str(), "last4": last4, "slot": slot.as_str(),
            "style": style.as_str(), "base_host": base_host });
        let entry =
            AuditEntry::member(Some(org), scope.member.user_id, "ai.key.set", None).with_meta(meta);
        let target = AuditEntry {
            target: Some(("model_key", k.id.to_string())),
            ..entry
        };
        tx.audit().record(target).await?;
        tx.commit().await?;
        Ok(PutKeyOutcome {
            status: a.status(scope).await?,
            models: list.map(|l| key_models(style, l)).unwrap_or_default(),
        })
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

fn key_models(style: AiProvider, list: Vec<ModelInfo>) -> Vec<KeyModel> {
    let defaults = ModelRole::ALL
        .iter()
        .map(|r| (*r, pick_default(style, *r, &list)))
        .collect::<Vec<_>>();
    list.into_iter()
        .map(|m| KeyModel {
            default_for: defaults
                .iter()
                .find(|(_, d)| d.as_deref() == Some(m.id.as_str()))
                .map(|(r, _)| *r),
            id: m.id,
            tools: m.tools,
        })
        .collect()
}

/// A stored connection and its live models list.
struct Live {
    conn: Conn,
    pin: Vec<SocketAddr>,
    /// `None`: a custom endpoint with no usable list (typed models).
    list: Option<Vec<ModelInfo>>,
}

/// The slot's connection and its live list (404 when empty). A list that answers clears a
/// failing key; a refused one marks it failing (502 `ai_key_failing`).
async fn live_models(a: &AiAccess, org: uuid::Uuid, slot: Slot) -> AppResult<Live> {
    let keys = a.uow.ai().keys(org).await?;
    let k = keys.get(slot).ok_or(AppError::NotFound)?;
    let conn = a.byok_conn(k).await?;
    let pin = a.pinned(&conn).await.map_err(|_| provider_down())?;
    let r = a
        .models
        .get(conn.style)
        .list_models(&AiAccess::endpoint(&conn, &pin))
        .await;
    let now = a.clock.now();
    match usable(r) {
        Ok(None) if !conn.custom => Err(provider_down()),
        Ok(list) => {
            if list.is_some() {
                let ai = a.uow.ai();
                ai.set_key_status(org, k.id, KeyStatus::Ok, now).await?;
            }
            Ok(Live { conn, pin, list })
        }
        Err(ModelError::Auth) => {
            let ai = a.uow.ai();
            ai.set_key_status(org, k.id, KeyStatus::Failing, now)
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

    /// The slot's live list; empty on a custom endpoint without one.
    pub async fn run(&self, scope: &OrgScope, slot: Slot) -> AppResult<Vec<KeyModel>> {
        let live = live_models(&self.access, scope.organisation.id, slot).await?;
        let style = live.conn.style;
        Ok(live.list.map(|l| key_models(style, l)).unwrap_or_default())
    }
}

/// Changes the slot's models, validated as on save: on the live list, or typed and
/// checked with one 1-token call.
pub struct PatchKey {
    access: Arc<AiAccess>,
}

impl PatchKey {
    pub fn new(access: Arc<AiAccess>) -> Self {
        Self { access }
    }

    pub async fn run(
        &self,
        scope: &OrgScope,
        slot: Slot,
        models: RoleModels,
    ) -> AppResult<AiStatus> {
        let a = &*self.access;
        let org = scope.organisation.id;
        let live = live_models(a, org, slot).await?;
        check_models(&models, live.list.as_deref())?;
        if live.list.is_none() {
            let ep = AiAccess::endpoint(&live.conn, &live.pin);
            one_token(a, live.conn.style, &ep, &models.chat).await?;
        }
        if !a.uow.ai().update_key_models(org, slot, &models).await? {
            return Err(AppError::NotFound);
        }
        a.status(scope).await
    }
}

/// Deletes the slot's connection (404 when empty); deleting the primary promotes the
/// backup. Audited `ai.key.delete` with the slot, style and host.
pub struct DeleteKey {
    access: Arc<AiAccess>,
}

impl DeleteKey {
    pub fn new(access: Arc<AiAccess>) -> Self {
        Self { access }
    }

    pub async fn run(&self, scope: &OrgScope, slot: Slot) -> AppResult<()> {
        let org = scope.organisation.id;
        let tx = self.access.uow.begin().await?;
        let keys = tx.ai().keys(org).await?;
        let k = keys.get(slot).ok_or(AppError::NotFound)?;
        let meta = json!({ "slot": slot.as_str(), "style": k.provider.as_str(),
            "base_host": k.base_url.as_deref().and_then(host_of) });
        if !tx.ai().delete_key(org, slot).await? {
            return Err(AppError::NotFound);
        }
        let entry = AuditEntry::member(Some(org), scope.member.user_id, "ai.key.delete", None)
            .with_meta(meta);
        tx.audit().record(entry).await?;
        tx.commit().await?;
        Ok(())
    }
}
