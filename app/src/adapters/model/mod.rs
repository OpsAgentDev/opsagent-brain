//! The `ModelProvider` adapters: Anthropic's Messages API, OpenAI's Responses API, both over
//! `reqwest` with one SSE parser, and the scripted fake. Request and response bodies, keys and
//! provider error text are never logged or returned; errors carry only a stable code.
use std::{sync::Arc, time::Duration};

use opsagent_core::model::{AiProvider, ModelError, ModelProvider};
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

fn http_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .connect_timeout(TIMEOUT)
        .read_timeout(TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
}

/// Sends `req`; a non-2xx answer becomes its `ModelError`, a transport failure or timeout an
/// `Outage`.
async fn send(req: reqwest::RequestBuilder) -> Result<reqwest::Response, ModelError> {
    let res = req.send().await.map_err(|_| ModelError::Outage)?;
    let status = res.status();
    if status.is_success() {
        return Ok(res);
    }
    let body: Value = res.json().await.unwrap_or(Value::Null);
    Err(status_error(status, &body))
}

/// The status mapping both providers share (dashboard-ai.md, The model port).
fn status_error(status: StatusCode, body: &Value) -> ModelError {
    match status.as_u16() {
        401 | 403 => ModelError::Auth,
        429 => ModelError::RateLimited,
        404 => ModelError::ModelGone,
        500..=599 => ModelError::Outage,
        _ if names_missing_model(&body["error"]) => ModelError::ModelGone,
        s => ModelError::Other(format!("http_{s}")),
    }
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
