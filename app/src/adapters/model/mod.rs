//! The `ModelProvider` adapters: Anthropic's Messages API, OpenAI's Chat Completions, both
//! over `reqwest` with one SSE parser, and the scripted fake. Request and response bodies, keys and
//! provider error text are never logged or returned; errors carry only a stable code.
use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};

use opsagent_core::model::{AiProvider, Endpoint, ModelError, ModelProvider};
use reqwest::StatusCode;
use serde_json::Value;

pub mod anthropic;
pub mod fake;
pub mod openai;
pub mod sse;

/// One adapter per provider; `get` picks the one a call plan names.
#[derive(Clone)]
pub struct ModelProviders {
    pub anthropic: Arc<dyn ModelProvider>,
    pub openai: Arc<dyn ModelProvider>,
}

impl ModelProviders {
    pub fn get(&self, p: AiProvider) -> Arc<dyn ModelProvider> {
        match p {
            AiProvider::Anthropic => self.anthropic.clone(),
            AiProvider::OpenAi => self.openai.clone(),
        }
    }
}

/// Connect and first byte (and any later stall) are cut at 30 s; the turn's own limit is
/// the caller's.
const TIMEOUT: Duration = Duration::from_secs(30);

fn builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .connect_timeout(TIMEOUT)
        .read_timeout(TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        // A proxy from the environment would connect around the pinned addresses.
        .no_proxy()
}

/// The client for `ep`: the shared one on system DNS, else a one-off that connects only to
/// `ep.pin`. Fails only if the TLS backend cannot initialise or the base has no host.
fn client_for(ep: &Endpoint) -> Result<reqwest::Client, ModelError> {
    static SHARED: OnceLock<reqwest::Client> = OnceLock::new();
    let failed = |_| ModelError::Other("http_client".into());
    if ep.pin.is_empty() {
        if let Some(c) = SHARED.get() {
            return Ok(c.clone());
        }
        let c = builder().build().map_err(failed)?;
        return Ok(SHARED.get_or_init(|| c).clone());
    }
    let url = reqwest::Url::parse(ep.base_url).map_err(|_| ModelError::Other("bad_url".into()))?;
    let host = url.host_str().ok_or(ModelError::Other("bad_url".into()))?;
    builder()
        .resolve_to_addrs(host, ep.pin)
        .build()
        .map_err(failed)
}

/// `{ep.base_url}{path}` on `ep`'s client.
fn request(
    ep: &Endpoint,
    method: reqwest::Method,
    path: &str,
) -> Result<reqwest::RequestBuilder, ModelError> {
    let url = format!("{}{path}", ep.base_url.trim_end_matches('/'));
    Ok(client_for(ep)?.request(method, url))
}

/// Sends `req`; a non-2xx answer becomes its `ModelError`, a transport failure or timeout an
/// `Outage`.
async fn send(req: reqwest::RequestBuilder) -> Result<reqwest::Response, ModelError> {
    let res = req.send().await.map_err(|_| ModelError::Outage)?;
    let status = res.status();
    if status.is_success() {
        return Ok(res);
    }
    let body = read_capped(res)
        .await
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Value::Null);
    Err(status_error(status, &body))
}

/// Size and time caps on provider calls; `OPSAGENT_AI_*` overrides, set once at boot.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ModelLimits {
    /// The most of a non-streamed body (an error or a models list) read from an endpoint.
    pub body_cap: usize,
    /// Every call that lists models, and every explanation, ends within this.
    pub call: Duration,
    /// One streamed model call ends within this.
    pub stream: Duration,
}

impl Default for ModelLimits {
    fn default() -> Self {
        Self {
            body_cap: 2 * 1024 * 1024,
            call: Duration::from_secs(120),
            stream: Duration::from_secs(300),
        }
    }
}

// shortcut: one process-wide value (config is per process); pass it in if it ever varies per call.
static LIMITS: OnceLock<ModelLimits> = OnceLock::new();

/// Sets the limits; the first call wins.
pub fn set_limits(l: ModelLimits) {
    let _ = LIMITS.set(l);
}

/// The limits set at boot, else the defaults.
pub fn limits() -> ModelLimits {
    *LIMITS.get_or_init(ModelLimits::default)
}

/// `res`'s body, read chunk by chunk; past `limits().body_cap` or broken, an `Outage`.
async fn read_capped(mut res: reqwest::Response) -> Result<Vec<u8>, ModelError> {
    let cap = limits().body_cap;
    let mut out = Vec::new();
    while let Some(chunk) = res.chunk().await.map_err(|_| ModelError::Outage)? {
        if out.len() + chunk.len() > cap {
            return Err(ModelError::Outage);
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// A models-list body as JSON: too big or broken is an `Outage`, unparseable `bad_response`
/// (so a custom endpoint gets `models_required`).
async fn list_body(res: reqwest::Response) -> Result<Value, ModelError> {
    let b = read_capped(res).await?;
    serde_json::from_slice(&b).map_err(|_| ModelError::Other("bad_response".into()))
}

/// `f` cut at `limit`; elapsed is an `Outage`.
async fn limited<T>(
    limit: Duration,
    f: impl std::future::Future<Output = Result<T, ModelError>>,
) -> Result<T, ModelError> {
    tokio::time::timeout(limit, f)
        .await
        .unwrap_or(Err(ModelError::Outage))
}

/// The status mapping both providers share (dashboard-ai.md, The model port).
fn status_error(status: StatusCode, body: &Value) -> ModelError {
    match status.as_u16() {
        401 | 403 => ModelError::Auth,
        // 529 and an overloaded 5xx are transient: retried like a rate limit before any backup.
        429 | 529 => ModelError::RateLimited,
        500..=599 if overloaded(&body["error"]) => ModelError::RateLimited,
        404 => ModelError::ModelGone,
        500..=599 => ModelError::Outage,
        _ if names_missing_model(&body["error"]) => ModelError::ModelGone,
        s => ModelError::Other(format!("http_{s}")),
    }
}

/// An error body naming overload (Anthropic's `type`, OpenAI's `code` or `type`).
fn overloaded(err: &Value) -> bool {
    let names = ["overloaded_error", "overloaded", "server_is_overloaded"];
    [&err["type"], &err["code"]]
        .iter()
        .any(|v| v.as_str().is_some_and(|n| names.contains(&n)))
}

/// A `not_found_error` whose message is about the model (read, never repeated).
fn names_missing_model(err: &Value) -> bool {
    err["type"].as_str() == Some("not_found_error")
        && err["message"].as_str().is_some_and(|m| m.contains("model"))
}

/// `body` parsed as JSON, else `bad_response`.
fn json(data: &str) -> Result<Value, ModelError> {
    serde_json::from_str(data).map_err(|_| ModelError::Other("bad_response".into()))
}

/// The tokens field `v[key]`, 0 when absent.
fn count(v: &Value, key: &str) -> u64 {
    v[key].as_u64().unwrap_or(0)
}
