//! Anthropic's Messages API (streamed, with prompt caching on the system block and the tool
//! list). Serves OpsAgent's key and BYOK.
use std::collections::BTreeMap;

use async_trait::async_trait;
use futures::{pin_mut, StreamExt};
use opsagent_core::model::{
    Endpoint, ModelError, ModelInfo, ModelMessage, ModelProvider, ModelRequest, ModelTurn, Part,
    StopReason, TextSink, ToolCall, Usage,
};
use serde_json::{json, Value};

use super::{count, json, limited, list_body, request, send, sse, CALL_LIMIT, STREAM_LIMIT};

pub const API_BASE: &str = "https://api.anthropic.com";

pub struct AnthropicModels {
    version: String,
}

impl AnthropicModels {
    pub fn new(version: &str) -> Self {
        Self {
            version: version.to_owned(),
        }
    }

    fn request(
        &self,
        ep: &Endpoint,
        method: reqwest::Method,
        path: &str,
    ) -> Result<reqwest::RequestBuilder, ModelError> {
        Ok(request(ep, method, path)?
            .header("x-api-key", ep.api_key)
            .header("anthropic-version", &self.version))
    }
}

const EPHEMERAL: &str = "ephemeral";

fn body(req: &ModelRequest) -> Value {
    let mut tools: Vec<Value> = req
        .tools
        .iter()
        .map(|t| json!({"name": t.name, "description": t.description, "input_schema": t.input_schema}))
        .collect();
    // One breakpoint after the tools caches them with the system prompt before them.
    if let Some(last) = tools.last_mut() {
        last["cache_control"] = json!({"type": EPHEMERAL});
    }
    let mut b = json!({
        "model": req.model,
        "max_tokens": req.max_tokens,
        "stream": true,
        "system": [{"type": "text", "text": req.system, "cache_control": {"type": EPHEMERAL}}],
        "messages": req.messages.iter().map(message).collect::<Vec<_>>(),
    });
    if !tools.is_empty() {
        b["tools"] = Value::Array(tools);
    }
    b
}

fn message(m: &ModelMessage) -> Value {
    let content: Vec<Value> = m
        .parts
        .iter()
        .filter_map(|p| match p {
            // The API refuses empty text blocks.
            Part::Text(t) if t.is_empty() => None,
            Part::Text(t) => Some(json!({"type": "text", "text": t})),
            Part::ToolCall(c) => {
                Some(json!({"type": "tool_use", "id": c.id, "name": c.name, "input": c.args}))
            }
            Part::ToolResult { call_id, content } => {
                Some(json!({"type": "tool_result", "tool_use_id": call_id, "content": content}))
            }
        })
        .collect();
    json!({"role": m.role.as_str(), "content": content})
}

/// The error an in-stream `error` event carries.
fn stream_error(err: &Value) -> ModelError {
    match err["type"].as_str() {
        Some("authentication_error" | "permission_error") => ModelError::Auth,
        Some("rate_limit_error") => ModelError::RateLimited,
        Some("not_found_error") => ModelError::ModelGone,
        Some("api_error" | "overloaded_error") => ModelError::Outage,
        _ => ModelError::Other("stream_error".into()),
    }
}

/// `message_start` and `message_delta` usage; later counts replace earlier ones.
fn add_usage(u: &mut Usage, v: &Value) {
    let set = |field: &mut u64, key: &str| {
        if let Some(n) = v[key].as_u64() {
            *field = n;
        }
    };
    set(&mut u.input_tokens, "input_tokens");
    set(&mut u.output_tokens, "output_tokens");
    set(&mut u.cache_read_tokens, "cache_read_input_tokens");
    set(&mut u.cache_write_tokens, "cache_creation_input_tokens");
}

/// A `tool_use` block being streamed: its id, name and the input JSON so far.
struct ToolBlock {
    id: String,
    name: String,
    json: String,
}

/// The turn so far, built from the stream's events.
struct Acc {
    turn: ModelTurn,
    tools: BTreeMap<u64, ToolBlock>,
}

impl Acc {
    fn on(&mut self, event: &str, v: &Value, sink: &mut dyn TextSink) -> Result<(), ModelError> {
        let index = count(v, "index");
        match event {
            "message_start" => add_usage(&mut self.turn.usage, &v["message"]["usage"]),
            "content_block_start" if v["content_block"]["type"] == "tool_use" => {
                let b = &v["content_block"];
                let s = |k: &str| b[k].as_str().unwrap_or_default().to_owned();
                let (id, name, json) = (s("id"), s("name"), String::new());
                self.tools.insert(index, ToolBlock { id, name, json });
            }
            "content_block_delta" => {
                let d = &v["delta"];
                let piece = |k: &str| d[k].as_str().unwrap_or_default();
                match d["type"].as_str() {
                    Some("text_delta") => {
                        sink.delta(piece("text"));
                        self.turn.text.push_str(piece("text"));
                    }
                    Some("input_json_delta") => {
                        if let Some(b) = self.tools.get_mut(&index) {
                            b.json.push_str(piece("partial_json"));
                        }
                    }
                    _ => {}
                }
            }
            "content_block_stop" => {
                if let Some(b) = self.tools.remove(&index) {
                    let args = if b.json.trim().is_empty() {
                        json!({})
                    } else {
                        json(&b.json)?
                    };
                    let (id, name) = (b.id, b.name);
                    self.turn.tool_calls.push(ToolCall { id, name, args });
                }
            }
            "message_delta" => {
                add_usage(&mut self.turn.usage, &v["usage"]);
                self.turn.stop = match v["delta"]["stop_reason"].as_str() {
                    Some("tool_use") => StopReason::ToolUse,
                    Some("max_tokens") => StopReason::MaxTokens,
                    _ => StopReason::EndTurn,
                };
            }
            "error" => return Err(stream_error(&v["error"])),
            _ => {}
        }
        Ok(())
    }
}

#[async_trait]
impl ModelProvider for AnthropicModels {
    async fn stream(
        &self,
        ep: &Endpoint<'_>,
        req: &ModelRequest,
        sink: &mut dyn TextSink,
    ) -> Result<ModelTurn, ModelError> {
        let http = self.request(ep, reqwest::Method::POST, "/v1/messages")?;
        limited(STREAM_LIMIT, async {
            let res = send(http.json(&body(req))).await?;
            let events = sse::events(res);
            pin_mut!(events);
            let mut acc = Acc {
                turn: ModelTurn {
                    text: String::new(),
                    tool_calls: Vec::new(),
                    usage: Usage::default(),
                    stop: StopReason::EndTurn,
                },
                tools: BTreeMap::new(),
            };
            while let Some(ev) = events.next().await {
                let (event, data) = ev?;
                match event.as_str() {
                    "ping" => {}
                    "message_stop" => return Ok(acc.turn),
                    _ => acc.on(&event, &json(&data)?, sink)?,
                }
            }
            // The body ended before `message_stop`.
            Err(ModelError::Outage)
        })
        .await
    }

    async fn list_models(&self, ep: &Endpoint<'_>) -> Result<Vec<ModelInfo>, ModelError> {
        let http = self.request(ep, reqwest::Method::GET, "/v1/models?limit=1000")?;
        let body = limited(CALL_LIMIT, async { list_body(send(http).await?).await }).await?;
        let ids = body["data"].as_array().into_iter().flatten();
        Ok(ids
            .filter_map(|m| m["id"].as_str())
            .map(|id| ModelInfo {
                id: id.to_owned(),
                tools: true,
            })
            .collect())
    }
}
