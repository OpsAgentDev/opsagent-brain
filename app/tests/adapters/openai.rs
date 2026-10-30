//! `OpenAiModels` against a wiremock Responses API.
use opsagent_brain::adapters::model::openai::OpenAiModels;
use opsagent_core::model::{
    ModelError, ModelInfo, ModelMessage, ModelProvider, ModelRequest, MsgRole, Part, StopReason,
    ToolCall, ToolDef, Usage,
};
use serde_json::{json, Value};
use wiremock::{
    matchers::{header, method, path},
    Mock, MockServer, ResponseTemplate,
};

use super::{sse_body, status_cases, Collect};

const KEY: &str = "sk-test";

fn models(server: &MockServer) -> OpenAiModels {
    OpenAiModels::new(&server.uri()).unwrap()
}

fn request() -> ModelRequest {
    ModelRequest {
        model: "gpt-5".into(),
        system: "You are OpsAgent.".into(),
        messages: vec![
            ModelMessage {
                role: MsgRole::User,
                parts: vec![Part::Text("hello".into())],
            },
            ModelMessage {
                role: MsgRole::Assistant,
                parts: vec![
                    Part::Text("Checking.".into()),
                    Part::ToolCall(ToolCall {
                        id: "call_0".into(),
                        name: "get_scan".into(),
                        args: json!({"id": "s"}),
                    }),
                ],
            },
            ModelMessage {
                role: MsgRole::User,
                parts: vec![Part::ToolResult {
                    call_id: "call_0".into(),
                    content: "<untrusted>x</untrusted>".into(),
                }],
            },
        ],
        tools: vec![ToolDef {
            name: "list_findings".into(),
            description: "Lists findings".into(),
            input_schema: json!({"type": "object"}),
        }],
        max_tokens: 2000,
    }
}

fn responses_ok(body: String) -> Mock {
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .and(header("authorization", format!("Bearer {KEY}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_raw(body, "text/event-stream"))
}

fn completed(usage: Value) -> (&'static str, Value) {
    (
        "response.completed",
        json!({"type": "response.completed", "response": {"status": "completed", "usage": usage}}),
    )
}

#[tokio::test]
async fn openai_sends_store_false_and_parses_function_call() {
    let server = MockServer::start().await;
    let body = sse_body(&[
        (
            "response.created",
            json!({"type": "response.created", "response": {"status": "in_progress"}}),
        ),
        (
            "response.output_text.delta",
            json!({"type": "response.output_text.delta", "delta": "One "}),
        ),
        (
            "response.output_text.delta",
            json!({"type": "response.output_text.delta", "delta": "moment."}),
        ),
        (
            "response.output_item.done",
            json!({"type": "response.output_item.done",
            "item": {"type": "message", "role": "assistant", "content": []}}),
        ),
        (
            "response.output_item.done",
            json!({"type": "response.output_item.done",
            "item": {"type": "function_call", "id": "fc_1", "call_id": "call_1",
                     "name": "list_findings", "arguments": "{\"limit\":1}"}}),
        ),
        completed(json!({"input_tokens": 50, "output_tokens": 20})),
    ]);
    responses_ok(body).expect(1).mount(&server).await;
    let mut sink = Collect::default();
    let turn = models(&server)
        .stream(KEY, &request(), &mut sink)
        .await
        .unwrap();
    assert_eq!(sink.0, vec!["One ", "moment."]);
    assert_eq!(turn.text, "One moment.");
    assert_eq!(turn.stop, StopReason::ToolUse);
    assert_eq!(
        turn.tool_calls,
        vec![ToolCall {
            id: "call_1".into(),
            name: "list_findings".into(),
            args: json!({"limit": 1}),
        }]
    );
    let reqs = server.received_requests().await.unwrap();
    let sent: Value = serde_json::from_slice(&reqs[0].body).unwrap();
    assert_eq!(sent["store"], false);
    assert_eq!(sent["stream"], true);
    assert_eq!(sent["model"], "gpt-5");
    assert_eq!(sent["instructions"], "You are OpsAgent.");
    assert_eq!(sent["max_output_tokens"], 2000);
    assert_eq!(
        sent["tools"],
        json!([{"type": "function", "name": "list_findings", "description": "Lists findings",
                "parameters": {"type": "object"}}])
    );
    assert_eq!(
        sent["input"],
        json!([
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "Checking."},
            {"type": "function_call", "call_id": "call_0", "name": "get_scan", "arguments": "{\"id\":\"s\"}"},
            {"type": "function_call_output", "call_id": "call_0", "output": "<untrusted>x</untrusted>"},
        ])
    );
}

#[tokio::test]
async fn openai_usage_maps_cached_tokens() {
    let server = MockServer::start().await;
    let body = sse_body(&[
        (
            "response.output_text.delta",
            json!({"type": "response.output_text.delta", "delta": "Hi"}),
        ),
        completed(
            json!({"input_tokens": 1000, "input_tokens_details": {"cached_tokens": 800},
                         "output_tokens": 15}),
        ),
    ]);
    responses_ok(body).mount(&server).await;
    let turn = models(&server)
        .stream(KEY, &request(), &mut Collect::default())
        .await
        .unwrap();
    assert_eq!(turn.stop, StopReason::EndTurn);
    // OpenAI counts cached tokens inside input_tokens; ours are disjoint.
    assert_eq!(
        turn.usage,
        Usage {
            input_tokens: 200,
            output_tokens: 15,
            cache_read_tokens: 800,
            cache_write_tokens: 0,
        }
    );
    // An incomplete response cut by the token limit is MaxTokens.
    let server = MockServer::start().await;
    let body = sse_body(&[(
        "response.incomplete",
        json!({"type": "response.incomplete", "response": {"status": "incomplete",
            "incomplete_details": {"reason": "max_output_tokens"},
            "usage": {"input_tokens": 5, "output_tokens": 2000}}}),
    )]);
    responses_ok(body).mount(&server).await;
    let turn = models(&server)
        .stream(KEY, &request(), &mut Collect::default())
        .await
        .unwrap();
    assert_eq!(turn.stop, StopReason::MaxTokens);
    assert_eq!(turn.usage.output_tokens, 2000);
}

#[tokio::test]
async fn openai_status_mapping_401_429_404_500() {
    for (status, body, want) in status_cases() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/responses"))
            .respond_with(ResponseTemplate::new(status).set_body_json(body.clone()))
            .mount(&server)
            .await;
        let got = models(&server)
            .stream(KEY, &request(), &mut Collect::default())
            .await;
        assert_eq!(got.unwrap_err(), want, "{status}");
    }
    // A stream that ends before `response.completed` is an outage.
    let server = MockServer::start().await;
    let body = sse_body(&[("response.output_text.delta", json!({"delta": "Hi"}))]);
    responses_ok(body).mount(&server).await;
    let got = models(&server)
        .stream(KEY, &request(), &mut Collect::default())
        .await;
    assert_eq!(got.unwrap_err(), ModelError::Outage);
}

#[tokio::test]
async fn openai_list_models_marks_tool_support() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .and(header("authorization", format!("Bearer {KEY}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"object": "list", "data": [
            {"id": "gpt-5", "object": "model"}, {"id": "gpt-4.1-mini", "object": "model"},
            {"id": "gpt-4o", "object": "model"}, {"id": "o3", "object": "model"},
            {"id": "o4-mini", "object": "model"}, {"id": "text-embedding-3-small", "object": "model"},
            {"id": "gpt-3.5-turbo", "object": "model"}
        ]})))
        .mount(&server)
        .await;
    let got = models(&server).list_models(KEY).await.unwrap();
    let tools: Vec<_> = got
        .iter()
        .map(|m: &ModelInfo| (m.id.as_str(), m.tools))
        .collect();
    assert_eq!(
        tools,
        vec![
            ("gpt-5", true),
            ("gpt-4.1-mini", true),
            ("gpt-4o", true),
            ("o3", true),
            ("o4-mini", true),
            ("text-embedding-3-small", false),
            ("gpt-3.5-turbo", false),
        ]
    );
}
