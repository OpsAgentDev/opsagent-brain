//! OpenAI-style Chat Completions (streamed, with the usage chunk requested), for the official
//! API and every compatible endpoint.
use std::collections::BTreeMap;

use async_trait::async_trait;
use futures::{pin_mut, StreamExt};
use opsagent_core::model::{
    Endpoint, ModelError, ModelInfo, ModelMessage, ModelProvider, ModelRequest, ModelTurn, MsgRole,
    Part, StopReason, TextSink, ToolCall, Usage,
};
use serde_json::{json, Value};

use super::{count, json, limited, list_body, request, send, sse};
use crate::config::OPENAI_TOOL_PREFIXES;

pub const API_BASE: &str = "https://api.openai.com/v1";

#[derive(Default)]
pub struct OpenAiModels;

impl OpenAiModels {
    pub fn new() -> Self {
        Self
    }
}

fn bearer(
    ep: &Endpoint,
    method: reqwest::Method,
    path: &str,
) -> Result<reqwest::RequestBuilder, ModelError> {
    Ok(request(ep, method, path)?.bearer_auth(ep.api_key))
}

fn body(ep: &Endpoint, req: &ModelRequest) -> Value {
    let tools: Vec<Value> = req
        .tools
        .iter()
        .map(|t| {
            json!({"type": "function", "function": {"name": t.name,
                   "description": t.description, "parameters": t.input_schema}})
        })
        .collect();
    let mut messages = vec![json!({"role": "system", "content": req.system})];
    messages.extend(req.messages.iter().flat_map(messages_of));
    let mut b = json!({
        "model": req.model,
        "messages": messages,
        "stream": true,
        "stream_options": {"include_usage": true},
    });
    // Plan ruling 7: reasoning models on the official API refuse `max_tokens`; many
    // compatible vendors read only `max_tokens`.
    let max = if ep.custom {
        "max_tokens"
    } else {
        "max_completion_tokens"
    };
    b[max] = json!(req.max_tokens);
    if !tools.is_empty() {
        b["tools"] = Value::Array(tools);
    }
    b
}

/// An assistant message as one message (text and tool calls together); a user message as
/// its text and one `tool` message per tool result, in order.
fn messages_of(m: &ModelMessage) -> Vec<Value> {
    if m.role == MsgRole::Assistant {
        let text: String = m.parts.iter().filter_map(text_of).collect();
        let calls: Vec<Value> = m
            .parts
            .iter()
            .filter_map(|p| match p {
                Part::ToolCall(c) => Some(json!({"id": c.id, "type": "function",
                    "function": {"name": c.name, "arguments": c.args.to_string()}})),
                _ => None,
            })
            .collect();
        return match (calls.is_empty(), text.is_empty()) {
            (true, true) => vec![],
            (true, false) => vec![json!({"role": "assistant", "content": text})],
            (false, _) => {
                let content = (!text.is_empty()).then_some(text);
                vec![json!({"role": "assistant", "content": content, "tool_calls": calls})]
            }
        };
    }
    m.parts
        .iter()
        .filter_map(|p| match p {
            Part::ToolResult { call_id, content } => {
                Some(json!({"role": "tool", "tool_call_id": call_id, "content": content}))
            }
            p => text_of(p)
                .filter(|t| !t.is_empty())
                .map(|t| json!({"role": "user", "content": t})),
        })
        .collect()
}

fn text_of(p: &Part) -> Option<&str> {
    match p {
        Part::Text(t) => Some(t),
        _ => None,
    }
}

/// `prompt_tokens` includes the cached ones; `Usage` keeps them apart.
fn usage(u: &Value) -> Usage {
    let cached = count(&u["prompt_tokens_details"], "cached_tokens");
    Usage {
        input_tokens: count(u, "prompt_tokens").saturating_sub(cached),
        output_tokens: count(u, "completion_tokens"),
        cache_read_tokens: cached,
        cache_write_tokens: 0,
    }
}

/// The error an in-stream `{"error": ...}` chunk carries (its `code` or `type`).
fn stream_error(err: &Value) -> ModelError {
    let names = [err["code"].as_str(), err["type"].as_str()];
    let any = |want: &[&str]| names.iter().flatten().any(|n| want.contains(n));
    if any(&["rate_limit_exceeded"]) {
        ModelError::RateLimited
    } else if any(&["server_error", "overloaded", "server_is_overloaded"]) {
        ModelError::Outage
    } else {
        ModelError::Other("stream_error".into())
    }
}

/// A tool call being streamed: id and name from its first fragment, arguments so far.
struct Pending {
    id: String,
    name: String,
    args: String,
}

/// The turn so far, built from the stream's chunks.
#[derive(Default)]
struct Acc {
    text: String,
    calls: BTreeMap<u64, Pending>,
    usage: Option<Usage>,
    stop: Option<StopReason>,
}

impl Acc {
    fn on(&mut self, v: &Value, sink: &mut dyn TextSink) -> Result<(), ModelError> {
        if v["error"].is_object() {
            return Err(stream_error(&v["error"]));
        }
        if v["usage"].is_object() {
            self.usage = Some(usage(&v["usage"]));
        }
        let choice = &v["choices"][0];
        let d = &choice["delta"];
        if let Some(t) = d["content"].as_str().filter(|t| !t.is_empty()) {
            sink.delta(t);
            self.text.push_str(t);
        }
        for c in d["tool_calls"].as_array().into_iter().flatten() {
            let s = |v: &Value| v.as_str().unwrap_or_default().to_owned();
            let p = self
                .calls
                .entry(count(c, "index"))
                .or_insert_with(|| Pending {
                    id: s(&c["id"]),
                    name: s(&c["function"]["name"]),
                    args: String::new(),
                });
            p.args
                .push_str(c["function"]["arguments"].as_str().unwrap_or_default());
        }
        if let Some(r) = choice["finish_reason"].as_str() {
            self.stop = Some(match r {
                "tool_calls" => StopReason::ToolUse,
                "length" => StopReason::MaxTokens,
                _ => StopReason::EndTurn,
            });
        }
        Ok(())
    }

    /// The finished turn; without a `finish_reason` the response was cut short.
    fn finish(self) -> Result<ModelTurn, ModelError> {
        let mut stop = self.stop.ok_or(ModelError::Outage)?;
        // Some gateways finish with `stop` after streaming tool calls.
        if !self.calls.is_empty() {
            stop = StopReason::ToolUse;
        }
        let mut tool_calls = Vec::with_capacity(self.calls.len());
        for (_, p) in self.calls {
            let args = match p.args.trim() {
                "" => json!({}),
                a => json(a)?,
            };
            tool_calls.push(ToolCall {
                id: p.id,
                name: p.name,
                args,
            });
        }
        let usage = self.usage.unwrap_or_else(|| {
            tracing::warn!(error_code = "usage_missing", "model stream sent no usage");
            Usage::default()
        });
        Ok(ModelTurn {
            text: self.text,
            tool_calls,
            usage,
            stop,
        })
    }
}

#[async_trait]
impl ModelProvider for OpenAiModels {
    async fn stream(
        &self,
        ep: &Endpoint<'_>,
        req: &ModelRequest,
        sink: &mut dyn TextSink,
    ) -> Result<ModelTurn, ModelError> {
        let http = bearer(ep, reqwest::Method::POST, "/chat/completions")?;
        let res = send(http.json(&body(ep, req))).await?;
        let events = sse::events(res);
        pin_mut!(events);
        let mut acc = Acc::default();
        while let Some(ev) = events.next().await {
            let (_, data) = ev?;
            if data.trim() == "[DONE]" {
                break;
            }
            acc.on(&json(&data)?, sink)?;
        }
        acc.finish()
    }

    async fn list_models(&self, ep: &Endpoint<'_>) -> Result<Vec<ModelInfo>, ModelError> {
        let http = bearer(ep, reqwest::Method::GET, "/models")?;
        let body = limited(async { list_body(send(http).await?).await }).await?;
        let ids = body["data"]
            .as_array()
            .ok_or_else(|| ModelError::Other("bad_response".into()))?;
        Ok(ids
            .iter()
            .filter_map(|m| m["id"].as_str())
            .map(|id| ModelInfo {
                id: id.to_owned(),
                tools: ep.custom || OPENAI_TOOL_PREFIXES.iter().any(|p| id.starts_with(p)),
            })
            .collect())
    }
}
