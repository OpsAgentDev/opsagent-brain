//! `AnthropicModels` against a wiremock Messages API.
use opsagent_brain::adapters::model::anthropic::AnthropicModels;
use opsagent_core::model::{
    Endpoint, ModelError, ModelInfo, ModelMessage, ModelProvider, ModelRequest, MsgRole, Part,
    StopReason, ToolCall, ToolDef, Usage,
};
use serde_json::{json, Value};
use wiremock::{
    matchers::{header, method, path},
    Mock, MockServer, ResponseTemplate,
};

use super::{sse_body, status_cases, Collect};

const KEY: &str = "sk-ant-test";

fn models() -> AnthropicModels {
    AnthropicModels::new("2023-06-01")
}

/// The official-style endpoint at `server` (leaked: a test's base outlives the call).
fn ep(server: &MockServer) -> Endpoint<'static> {
    Endpoint {
        base_url: server.uri().leak(),
        api_key: KEY,
        custom: false,
        pin: &[],
    }
}

fn tool(name: &str) -> ToolDef {
    ToolDef {
        name: name.into(),
        description: format!("{name} tool"),
        input_schema: json!({"type": "object"}),
    }
}

fn request(tools: Vec<ToolDef>) -> ModelRequest {
    ModelRequest {
        model: "claude-haiku-5-5".into(),
        system: "You are OpsAgent.".into(),
        messages: vec![ModelMessage {
            role: MsgRole::User,
            parts: vec![Part::Text("hello".into())],
        }],
        tools,
        max_tokens: 600,
    }
}

fn messages_ok(body: String) -> Mock {
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .and(header("x-api-key", KEY))
        .and(header("anthropic-version", "2023-06-01"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(body, "text/event-stream"))
}

async fn sent_body(server: &MockServer) -> Value {
    let reqs = server.received_requests().await.unwrap();
    serde_json::from_slice(&reqs[0].body).unwrap()
}

#[tokio::test]
async fn anthropic_streams_text_and_usage() {
    let server = MockServer::start().await;
    let body = sse_body(&[
        (
            "message_start",
            json!({"type": "message_start", "message": {"id": "m1", "usage": {
            "input_tokens": 120, "output_tokens": 1,
            "cache_read_input_tokens": 900, "cache_creation_input_tokens": 300}}}),
        ),
        (
            "content_block_start",
            json!({"type": "content_block_start", "index": 0,
            "content_block": {"type": "text", "text": ""}}),
        ),
        ("ping", json!({"type": "ping"})),
        (
            "content_block_delta",
            json!({"type": "content_block_delta", "index": 0,
            "delta": {"type": "text_delta", "text": "Hel"}}),
        ),
        (
            "content_block_delta",
            json!({"type": "content_block_delta", "index": 0,
            "delta": {"type": "text_delta", "text": "lo."}}),
        ),
        (
            "content_block_stop",
            json!({"type": "content_block_stop", "index": 0}),
        ),
        (
            "message_delta",
            json!({"type": "message_delta",
            "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 42}}),
        ),
        ("message_stop", json!({"type": "message_stop"})),
    ]);
    messages_ok(body).expect(1).mount(&server).await;
    let mut sink = Collect::default();
    let turn = models()
        .stream(
            &ep(&server),
            &request(vec![tool("a"), tool("b")]),
            &mut sink,
        )
        .await
        .unwrap();
    assert_eq!(sink.0, vec!["Hel", "lo."]);
    assert_eq!(turn.text, "Hello.");
    assert_eq!(turn.stop, StopReason::EndTurn);
    assert!(turn.tool_calls.is_empty());
    assert_eq!(
        turn.usage,
        Usage {
            input_tokens: 120,
            output_tokens: 42,
            cache_read_tokens: 900,
            cache_write_tokens: 300,
        }
    );
    let sent = sent_body(&server).await;
    assert_eq!(sent["stream"], true);
    assert_eq!(sent["model"], "claude-haiku-5-5");
    assert_eq!(sent["max_tokens"], 600);
    assert_eq!(
        sent["system"],
        json!([{"type": "text", "text": "You are OpsAgent.", "cache_control": {"type": "ephemeral"}}])
    );
    assert_eq!(sent["tools"][0].get("cache_control"), None);
    assert_eq!(
        sent["tools"][1]["cache_control"],
        json!({"type": "ephemeral"})
    );
    assert_eq!(sent["tools"][1]["input_schema"], json!({"type": "object"}));
    assert_eq!(
        sent["messages"],
        json!([{"role": "user", "content": [{"type": "text", "text": "hello"}]}])
    );
}

#[tokio::test]
async fn anthropic_assembles_tool_use_from_json_deltas() {
    let server = MockServer::start().await;
    let body = sse_body(&[
        (
            "message_start",
            json!({"type": "message_start", "message": {"usage": {"input_tokens": 10, "output_tokens": 1}}}),
        ),
        (
            "content_block_start",
            json!({"type": "content_block_start", "index": 0,
            "content_block": {"type": "text", "text": ""}}),
        ),
        (
            "content_block_delta",
            json!({"type": "content_block_delta", "index": 0,
            "delta": {"type": "text_delta", "text": "Looking."}}),
        ),
        (
            "content_block_stop",
            json!({"type": "content_block_stop", "index": 0}),
        ),
        (
            "content_block_start",
            json!({"type": "content_block_start", "index": 1,
            "content_block": {"type": "tool_use", "id": "toolu_1", "name": "list_findings", "input": {}}}),
        ),
        (
            "content_block_delta",
            json!({"type": "content_block_delta", "index": 1,
            "delta": {"type": "input_json_delta", "partial_json": "{\"lim"}}),
        ),
        (
            "content_block_delta",
            json!({"type": "content_block_delta", "index": 1,
            "delta": {"type": "input_json_delta", "partial_json": "it\": 1}"}}),
        ),
        (
            "content_block_stop",
            json!({"type": "content_block_stop", "index": 1}),
        ),
        (
            "content_block_start",
            json!({"type": "content_block_start", "index": 2,
            "content_block": {"type": "tool_use", "id": "toolu_2", "name": "list_connections", "input": {}}}),
        ),
        (
            "content_block_stop",
            json!({"type": "content_block_stop", "index": 2}),
        ),
        (
            "message_delta",
            json!({"type": "message_delta",
            "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 30}}),
        ),
        ("message_stop", json!({"type": "message_stop"})),
    ]);
    messages_ok(body).mount(&server).await;
    let mut req = request(vec![tool("list_findings")]);
    req.messages.push(ModelMessage {
        role: MsgRole::Assistant,
        parts: vec![Part::ToolCall(ToolCall {
            id: "toolu_0".into(),
            name: "get_scan".into(),
            args: json!({"id": "s"}),
        })],
    });
    req.messages.push(ModelMessage {
        role: MsgRole::User,
        parts: vec![Part::ToolResult {
            call_id: "toolu_0".into(),
            content: "<untrusted>x</untrusted>".into(),
        }],
    });
    let turn = models()
        .stream(&ep(&server), &req, &mut Collect::default())
        .await
        .unwrap();
    assert_eq!(turn.stop, StopReason::ToolUse);
    assert_eq!(turn.text, "Looking.");
    assert_eq!(
        turn.tool_calls,
        vec![
            ToolCall {
                id: "toolu_1".into(),
                name: "list_findings".into(),
                args: json!({"limit": 1}),
            },
            ToolCall {
                id: "toolu_2".into(),
                name: "list_connections".into(),
                args: json!({}),
            },
        ]
    );
    let sent = sent_body(&server).await;
    assert_eq!(
        sent["messages"][1],
        json!({"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_0", "name": "get_scan", "input": {"id": "s"}}]})
    );
    assert_eq!(
        sent["messages"][2],
        json!({"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_0", "content": "<untrusted>x</untrusted>"}]})
    );
}

#[tokio::test]
async fn anthropic_status_mapping_401_429_404_500() {
    for (status, body, want) in status_cases() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(status).set_body_json(body.clone()))
            .mount(&server)
            .await;
        let got = models()
            .stream(&ep(&server), &request(vec![]), &mut Collect::default())
            .await;
        assert_eq!(got.unwrap_err(), want, "{status}");
    }
    // A 400 naming a missing model is the model gone too.
    let server = MockServer::start().await;
    let gone = json!({"type": "error", "error": {"type": "not_found_error", "message": "model: claude-x"}});
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(400).set_body_json(gone))
        .mount(&server)
        .await;
    let got = models()
        .stream(&ep(&server), &request(vec![]), &mut Collect::default())
        .await;
    assert_eq!(got.unwrap_err(), ModelError::ModelGone);
    // An overloaded error mid-stream is an outage.
    let server = MockServer::start().await;
    let body = sse_body(&[(
        "error",
        json!({"type": "error", "error": {"type": "overloaded_error", "message": "Overloaded"}}),
    )]);
    messages_ok(body).mount(&server).await;
    let got = models()
        .stream(&ep(&server), &request(vec![]), &mut Collect::default())
        .await;
    assert_eq!(got.unwrap_err(), ModelError::Outage);
    // Nothing listening is an outage too.
    let down = Endpoint {
        base_url: "http://127.0.0.1:1",
        ..ep(&server)
    };
    let got = models()
        .stream(&down, &request(vec![]), &mut Collect::default())
        .await;
    assert_eq!(got.unwrap_err(), ModelError::Outage);
}

#[tokio::test]
async fn anthropic_list_models_marks_tool_support() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .and(header("x-api-key", KEY))
        .and(header("anthropic-version", "2023-06-01"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": "claude-sonnet-5-5", "type": "model"}, {"id": "claude-haiku-5-5", "type": "model"}],
            "has_more": false
        })))
        .mount(&server)
        .await;
    let got = models().list_models(&ep(&server)).await.unwrap();
    let info = |id: &str| ModelInfo {
        id: id.into(),
        tools: true,
    };
    assert_eq!(
        got,
        vec![info("claude-sonnet-5-5"), info("claude-haiku-5-5")]
    );
}
