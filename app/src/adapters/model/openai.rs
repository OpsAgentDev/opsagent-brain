//! OpenAI's Responses API (streamed, `store: false`). Serves BYOK only.
use async_trait::async_trait;
use futures::{pin_mut, StreamExt};
use opsagent_core::model::{
    ModelError, ModelInfo, ModelMessage, ModelProvider, ModelRequest, ModelTurn, MsgRole, Part,
    StopReason, TextSink, ToolCall, Usage,
};
use serde_json::{json, Value};

use super::{count, http_client, json, send, sse};
use crate::config::OPENAI_TOOL_PREFIXES;

pub const API_BASE: &str = "https://api.openai.com";

pub struct OpenAiModels {
    base: String,
    http: reqwest::Client,
}

impl OpenAiModels {
    /// Fails only if the TLS backend cannot initialise.
    pub fn new(base: &str) -> Result<Self, reqwest::Error> {
        Ok(Self {
            base: base.trim_end_matches('/').to_owned(),
            http: http_client()?,
        })
    }

    fn request(&self, method: reqwest::Method, path: &str, key: &str) -> reqwest::RequestBuilder {
        let url = format!("{}{path}", self.base);
        self.http.request(method, url).bearer_auth(key)
    }
}

fn body(req: &ModelRequest) -> Value {
    let tools: Vec<Value> = req
        .tools
        .iter()
        .map(|t| {
            json!({"type": "function", "name": t.name, "description": t.description,
                   "parameters": t.input_schema})
        })
        .collect();
    let mut b = json!({
        "model": req.model,
        "instructions": req.system,
        "input": req.messages.iter().flat_map(items).collect::<Vec<_>>(),
        "max_output_tokens": req.max_tokens,
        "stream": true,
        "store": false,
    });
    if !tools.is_empty() {
        b["tools"] = Value::Array(tools);
    }
    b
}

/// One input item per part: text as a role message, tool calls and results as their items.
fn items(m: &ModelMessage) -> Vec<Value> {
    let role = m.role.as_str();
    m.parts
        .iter()
        .filter_map(|p| match p {
            Part::Text(t) if t.is_empty() => None,
            Part::Text(t) => Some(json!({"role": role, "content": t})),
            Part::ToolCall(c) if m.role == MsgRole::Assistant => Some(json!({
                "type": "function_call", "call_id": c.id, "name": c.name,
                "arguments": c.args.to_string()})),
            Part::ToolCall(_) => None,
            Part::ToolResult { call_id, content } => Some(json!({
                "type": "function_call_output", "call_id": call_id, "output": content})),
        })
        .collect()
}

/// `input_tokens` includes the cached ones; `Usage` keeps them apart.
fn usage(u: &Value) -> Usage {
    let cached = count(&u["input_tokens_details"], "cached_tokens");
    Usage {
        input_tokens: count(u, "input_tokens").saturating_sub(cached),
        output_tokens: count(u, "output_tokens"),
        cache_read_tokens: cached,
        cache_write_tokens: 0,
    }
}

/// The error a `response.failed` or `error` event carries.
fn stream_error(code: Option<&str>) -> ModelError {
    match code {
        Some("rate_limit_exceeded") => ModelError::RateLimited,
        Some("server_error" | "server_is_overloaded") => ModelError::Outage,
        _ => ModelError::Other("stream_error".into()),
    }
}

#[async_trait]
impl ModelProvider for OpenAiModels {
    async fn stream(
        &self,
        api_key: &str,
        req: &ModelRequest,
        sink: &mut dyn TextSink,
    ) -> Result<ModelTurn, ModelError> {
        let http = self.request(reqwest::Method::POST, "/v1/responses", api_key);
        let res = send(http.json(&body(req))).await?;
        let events = sse::events(res);
        pin_mut!(events);
        let mut text = String::new();
        let mut tool_calls = Vec::new();
        while let Some(ev) = events.next().await {
            let (event, data) = ev?;
            let v = json(&data)?;
            let stop = match event.as_str() {
                "response.output_text.delta" => {
                    let t = v["delta"].as_str().unwrap_or_default();
                    sink.delta(t);
                    text.push_str(t);
                    continue;
                }
                "response.output_item.done" if v["item"]["type"] == "function_call" => {
                    let it = &v["item"];
                    let s = |k: &str| it[k].as_str().unwrap_or_default().to_owned();
                    let args = match it["arguments"].as_str().map(str::trim) {
                        None | Some("") => json!({}),
                        Some(a) => json(a)?,
                    };
                    tool_calls.push(ToolCall {
                        id: s("call_id"),
                        name: s("name"),
                        args,
                    });
                    continue;
                }
                "response.completed" if !tool_calls.is_empty() => StopReason::ToolUse,
                "response.completed" => StopReason::EndTurn,
                "response.incomplete" => {
                    let reason = v["response"]["incomplete_details"]["reason"].as_str();
                    if reason == Some("max_output_tokens") {
                        StopReason::MaxTokens
                    } else {
                        StopReason::EndTurn
                    }
                }
                "response.failed" => {
                    return Err(stream_error(v["response"]["error"]["code"].as_str()))
                }
                "error" => return Err(stream_error(v["code"].as_str())),
                _ => continue,
            };
            let usage = usage(&v["response"]["usage"]);
            return Ok(ModelTurn {
                text,
                tool_calls,
                usage,
                stop,
            });
        }
        // The body ended before the response did.
        Err(ModelError::Outage)
    }

    async fn list_models(&self, api_key: &str) -> Result<Vec<ModelInfo>, ModelError> {
        let res = send(self.request(reqwest::Method::GET, "/v1/models", api_key)).await?;
        let body: Value = res.json().await.map_err(|_| ModelError::Outage)?;
        let ids = body["data"].as_array().into_iter().flatten();
        Ok(ids
            .filter_map(|m| m["id"].as_str())
            .map(|id| ModelInfo {
                id: id.to_owned(),
                tools: OPENAI_TOOL_PREFIXES.iter().any(|p| id.starts_with(p)),
            })
            .collect())
    }
}
