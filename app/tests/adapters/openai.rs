//! `OpenAiModels` against a wiremock Chat Completions API.
use std::net::SocketAddr;

use opsagent_brain::adapters::model::openai::OpenAiModels;
use opsagent_core::model::{
    Endpoint, ModelError, ModelInfo, ModelMessage, ModelProvider, ModelRequest, MsgRole, Part,
    StopReason, ToolCall, ToolDef, Usage,
};
use serde_json::{json, Value};
use wiremock::{
    matchers::{header, method, path},
    Mock, MockServer, ResponseTemplate,
};

use super::{status_cases, Collect};

const KEY: &str = "sk-test";

fn ep(base: &str, custom: bool) -> Endpoint<'_> {
    Endpoint {
        base_url: base,
        api_key: KEY,
        custom,
        pin: &[],
    }
}

fn base(server: &MockServer) -> String {
    format!("{}/v1", server.uri())
}

fn request(system: &str) -> ModelRequest {
    ModelRequest {
        model: "gpt-5".into(),
        system: system.into(),
        messages: vec![ModelMessage {
            role: MsgRole::User,
            parts: vec![Part::Text("hello".into())],
        }],
        tools: vec![ToolDef {
            name: "list_findings".into(),
            description: "Lists findings".into(),
            input_schema: json!({"type": "object"}),
        }],
        max_tokens: 2000,
    }
}

/// A Chat Completions SSE body: one `data:` line per chunk, then `[DONE]`.
fn chunks(cs: &[Value]) -> String {
    let mut s: String = cs.iter().map(|c| format!("data: {c}\n\n")).collect();
    s.push_str("data: [DONE]\n\n");
    s
}

fn delta(d: Value) -> Value {
    json!({"choices": [{"index": 0, "delta": d, "finish_reason": null}]})
}

fn finish(reason: &str) -> Value {
    json!({"choices": [{"index": 0, "delta": {}, "finish_reason": reason}]})
}

fn completions_ok(prefix: &str, body: String) -> Mock {
    Mock::given(method("POST"))
        .and(path(format!("{prefix}/chat/completions")))
        .and(header("authorization", format!("Bearer {KEY}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_raw(body, "text/event-stream"))
}

async fn sent_body(server: &MockServer) -> Value {
    let reqs = server.received_requests().await.unwrap();
    serde_json::from_slice(&reqs[0].body).unwrap()
}

#[tokio::test]
async fn chat_completions_streams_text_and_final_usage() {
    let server = MockServer::start().await;
    let body = chunks(&[
        delta(json!({"role": "assistant", "content": ""})),
        delta(json!({"content": "Hel"})),
        delta(json!({"content": "lo"})),
        finish("stop"),
        json!({"choices": [], "usage": {"prompt_tokens": 100, "completion_tokens": 7,
            "prompt_tokens_details": {"cached_tokens": 40}}}),
    ]);
    completions_ok("/v1", body).expect(1).mount(&server).await;
    let mut sink = Collect::default();
    let b = base(&server);
    let turn = OpenAiModels::new()
        .stream(&ep(&b, false), &request("sys"), &mut sink)
        .await
        .unwrap();
    assert_eq!(sink.0.concat(), "Hello");
    assert_eq!(turn.text, "Hello");
    assert_eq!(turn.stop, StopReason::EndTurn);
    assert!(turn.tool_calls.is_empty());
    assert_eq!(
        turn.usage,
        Usage {
            input_tokens: 60,
            output_tokens: 7,
            cache_read_tokens: 40,
            cache_write_tokens: 0,
        }
    );
    let sent = sent_body(&server).await;
    assert_eq!(sent["stream"], true);
    assert_eq!(sent["stream_options"]["include_usage"], true);
    assert_eq!(sent["model"], "gpt-5");
    assert_eq!(
        sent["messages"][0],
        json!({"role": "system", "content": "sys"})
    );
    assert_eq!(
        sent["messages"][1],
        json!({"role": "user", "content": "hello"})
    );
    assert_eq!(
        sent["tools"],
        json!([{"type": "function", "function": {"name": "list_findings",
                "description": "Lists findings", "parameters": {"type": "object"}}}])
    );
}

#[tokio::test]
async fn chat_completions_assembles_tool_calls_by_index() {
    let server = MockServer::start().await;
    let call =
        |i: u64, f: Value| delta(json!({"tool_calls": [json!({"index": i, "function": f})]}));
    let first = |i: u64, id: &str, name: &str| {
        delta(
            json!({"tool_calls": [{"index": i, "id": id, "type": "function",
            "function": {"name": name, "arguments": ""}}]}),
        )
    };
    let body = chunks(&[
        first(0, "call_a", "list_findings"),
        call(0, json!({"arguments": "{\"li"})),
        first(1, "call_b", "list_connections"),
        call(0, json!({"arguments": "mit\":"})),
        call(0, json!({"arguments": " 1}"})),
        finish("tool_calls"),
    ]);
    completions_ok("/v1", body).mount(&server).await;
    let b = base(&server);
    let turn = OpenAiModels::new()
        .stream(&ep(&b, false), &request("s"), &mut Collect::default())
        .await
        .unwrap();
    assert_eq!(turn.stop, StopReason::ToolUse);
    assert_eq!(
        turn.tool_calls,
        vec![
            ToolCall {
                id: "call_a".into(),
                name: "list_findings".into(),
                args: json!({"limit": 1}),
            },
            ToolCall {
                id: "call_b".into(),
                name: "list_connections".into(),
                args: json!({}),
            },
        ]
    );
}

#[tokio::test]
async fn chat_completions_tool_calls_with_stop_finish_is_tool_use() {
    let server = MockServer::start().await;
    let body = chunks(&[
        delta(
            json!({"tool_calls": [{"index": 0, "id": "call_a", "type": "function",
            "function": {"name": "list_findings", "arguments": "{}"}}]}),
        ),
        finish("stop"),
    ]);
    completions_ok("/v1", body).mount(&server).await;
    let b = base(&server);
    let turn = OpenAiModels::new()
        .stream(&ep(&b, true), &request("s"), &mut Collect::default())
        .await
        .unwrap();
    assert_eq!(turn.stop, StopReason::ToolUse);
    assert_eq!(turn.tool_calls.len(), 1);
}

#[tokio::test]
async fn chat_completions_sends_tool_history() {
    let server = MockServer::start().await;
    completions_ok("/v1", chunks(&[finish("stop")]))
        .mount(&server)
        .await;
    let mut req = request("s");
    let call = |id: &str| ToolCall {
        id: id.into(),
        name: "get_scan".into(),
        args: json!({"id": "s"}),
    };
    req.messages.push(ModelMessage {
        role: MsgRole::Assistant,
        parts: vec![
            Part::Text("Checking.".into()),
            Part::ToolCall(call("call_0")),
        ],
    });
    req.messages.push(ModelMessage {
        role: MsgRole::User,
        parts: vec![Part::ToolResult {
            call_id: "call_0".into(),
            content: "<untrusted>x</untrusted>".into(),
        }],
    });
    req.messages.push(ModelMessage {
        role: MsgRole::Assistant,
        parts: vec![Part::ToolCall(call("call_1"))],
    });
    let b = base(&server);
    OpenAiModels::new()
        .stream(&ep(&b, false), &req, &mut Collect::default())
        .await
        .unwrap();
    let sent = sent_body(&server).await;
    let fc = |id: &str| {
        json!({"id": id, "type": "function",
               "function": {"name": "get_scan", "arguments": "{\"id\":\"s\"}"}})
    };
    assert_eq!(
        sent["messages"],
        json!([
            {"role": "system", "content": "s"},
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "Checking.", "tool_calls": [fc("call_0")]},
            {"role": "tool", "tool_call_id": "call_0", "content": "<untrusted>x</untrusted>"},
            {"role": "assistant", "content": null, "tool_calls": [fc("call_1")]},
        ])
    );
}

#[tokio::test]
async fn chat_completions_finish_length_is_max_tokens() {
    let server = MockServer::start().await;
    let body = chunks(&[delta(json!({"content": "cut"})), finish("length")]);
    completions_ok("/v1", body).mount(&server).await;
    let b = base(&server);
    let turn = OpenAiModels::new()
        .stream(&ep(&b, false), &request("s"), &mut Collect::default())
        .await
        .unwrap();
    assert_eq!(turn.stop, StopReason::MaxTokens);
    assert_eq!(turn.text, "cut");
}

#[tokio::test]
async fn chat_completions_without_usage_chunk_ends_turn() {
    let server = MockServer::start().await;
    let body = chunks(&[delta(json!({"content": "Hi"})), finish("stop")]);
    completions_ok("/v1", body).mount(&server).await;
    let b = base(&server);
    let turn = OpenAiModels::new()
        .stream(&ep(&b, true), &request("s"), &mut Collect::default())
        .await
        .unwrap();
    assert_eq!(turn.text, "Hi");
    assert_eq!(turn.stop, StopReason::EndTurn);
    assert_eq!(turn.usage, Usage::default());
    // The body may also end, after a finish_reason, with no `[DONE]`.
    let server = MockServer::start().await;
    let body = format!("data: {}\n\n", finish("stop"));
    completions_ok("/v1", body).mount(&server).await;
    let b = base(&server);
    let turn = OpenAiModels::new()
        .stream(&ep(&b, true), &request("s"), &mut Collect::default())
        .await
        .unwrap();
    assert_eq!(turn.stop, StopReason::EndTurn);
}

#[tokio::test]
async fn chat_completions_error_chunk_maps() {
    let cases = [
        (
            json!({"code": "rate_limit_exceeded"}),
            ModelError::RateLimited,
        ),
        (json!({"type": "server_error"}), ModelError::Outage),
        (json!({"code": "overloaded"}), ModelError::RateLimited),
        (
            json!({"code": "server_is_overloaded"}),
            ModelError::RateLimited,
        ),
        (
            json!({"code": "invalid_prompt", "message": "provider text"}),
            ModelError::Other("stream_error".into()),
        ),
    ];
    for (err, want) in cases {
        let server = MockServer::start().await;
        let body = chunks(&[delta(json!({"content": "x"})), json!({"error": err})]);
        completions_ok("/v1", body).mount(&server).await;
        let b = base(&server);
        let got = OpenAiModels::new()
            .stream(&ep(&b, false), &request("s"), &mut Collect::default())
            .await;
        assert_eq!(got.unwrap_err(), want, "{err}");
    }
}

#[tokio::test]
async fn max_tokens_field_by_endpoint() {
    for custom in [false, true] {
        let server = MockServer::start().await;
        completions_ok("/v1", chunks(&[finish("stop")]))
            .mount(&server)
            .await;
        let b = base(&server);
        OpenAiModels::new()
            .stream(&ep(&b, custom), &request("s"), &mut Collect::default())
            .await
            .unwrap();
        let sent = sent_body(&server).await;
        let (on, off) = match custom {
            false => ("max_completion_tokens", "max_tokens"),
            true => ("max_tokens", "max_completion_tokens"),
        };
        assert_eq!(sent[on], 2000, "custom={custom}");
        assert_eq!(sent.get(off), None, "custom={custom}");
    }
}

#[tokio::test]
async fn custom_base_url_path_respected() {
    let server = MockServer::start().await;
    completions_ok("/api/v1", chunks(&[finish("stop")]))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": [{"id": "m"}]})))
        .expect(1)
        .mount(&server)
        .await;
    let b = format!("{}/api/v1", server.uri());
    let m = OpenAiModels::new();
    m.stream(&ep(&b, true), &request("s"), &mut Collect::default())
        .await
        .unwrap();
    assert_eq!(m.list_models(&ep(&b, true)).await.unwrap().len(), 1);
}

#[tokio::test]
async fn list_models_tool_prefixes_only_on_official() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .and(header("authorization", format!("Bearer {KEY}").as_str()))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"object": "list", "data": [
                {"id": "gpt-5", "object": "model"}, {"id": "gpt-4.1-mini", "object": "model"},
                {"id": "gpt-4o", "object": "model"}, {"id": "o3", "object": "model"},
                {"id": "o4-mini", "object": "model"}, {"id": "llama-3", "object": "model"},
                {"id": "gpt-3.5-turbo", "object": "model"}
            ]})),
        )
        .mount(&server)
        .await;
    let b = base(&server);
    let tools = |got: Vec<ModelInfo>| -> Vec<(String, bool)> {
        got.into_iter().map(|m| (m.id, m.tools)).collect()
    };
    let official = OpenAiModels::new().list_models(&ep(&b, false)).await;
    let want = |llama: bool, old: bool| {
        [
            ("gpt-5", true),
            ("gpt-4.1-mini", true),
            ("gpt-4o", true),
            ("o3", true),
            ("o4-mini", true),
            ("llama-3", llama),
            ("gpt-3.5-turbo", old),
        ]
        .map(|(id, t)| (id.to_owned(), t))
        .to_vec()
    };
    assert_eq!(tools(official.unwrap()), want(false, false));
    let custom = OpenAiModels::new().list_models(&ep(&b, true)).await;
    assert_eq!(tools(custom.unwrap()), want(true, true));
    // A list with no `data` is a bad response.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(&server)
        .await;
    let b = base(&server);
    let got = OpenAiModels::new().list_models(&ep(&b, true)).await;
    assert_eq!(got, Err(ModelError::Other("bad_response".into())));
}

#[tokio::test]
async fn pinned_resolution_is_used() {
    let server = MockServer::start().await;
    completions_ok(
        "/v1",
        chunks(&[delta(json!({"content": "pinned"})), finish("stop")]),
    )
    .expect(1)
    .mount(&server)
    .await;
    let port = server.address().port();
    let b = format!("http://pinned.example:{port}/v1");
    let pin = [SocketAddr::from(([127, 0, 0, 1], port))];
    let pinned = Endpoint {
        base_url: &b,
        api_key: KEY,
        custom: true,
        pin: &pin,
    };
    let turn = OpenAiModels::new()
        .stream(&pinned, &request("s"), &mut Collect::default())
        .await
        .unwrap();
    assert_eq!(turn.text, "pinned");
}

#[tokio::test]
async fn openai_status_mapping_401_429_404_500() {
    for (status, body, want) in status_cases() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(status).set_body_json(body.clone()))
            .mount(&server)
            .await;
        let b = base(&server);
        let got = OpenAiModels::new()
            .stream(&ep(&b, false), &request("s"), &mut Collect::default())
            .await;
        assert_eq!(got.unwrap_err(), want, "{status}");
    }
    // A body that ends before any finish_reason is an outage.
    let server = MockServer::start().await;
    let body = format!("data: {}\n\n", delta(json!({"content": "Hi"})));
    completions_ok("/v1", body).mount(&server).await;
    let b = base(&server);
    let got = OpenAiModels::new()
        .stream(&ep(&b, false), &request("s"), &mut Collect::default())
        .await;
    assert_eq!(got.unwrap_err(), ModelError::Outage);
}

#[tokio::test]
async fn oversized_or_unparseable_list_and_endless_line_are_bounded() {
    let server = MockServer::start().await;
    let big = format!("{{\"data\":[\"{}\"]}}", "a".repeat(3 * 1024 * 1024));
    Mock::given(method("GET"))
        .and(path("/big/models"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(big, "application/json"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/html/models"))
        .respond_with(ResponseTemplate::new(200).set_body_raw("<html>hi</html>", "text/html"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/big/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            "data: ".to_owned() + &"x".repeat(2 * 1024 * 1024),
            "text/event-stream",
        ))
        .mount(&server)
        .await;
    let m = OpenAiModels::new();
    let big = format!("{}/big", server.uri());
    assert_eq!(
        m.list_models(&ep(&big, true)).await,
        Err(ModelError::Outage)
    );
    let html = format!("{}/html", server.uri());
    let got = m.list_models(&ep(&html, true)).await;
    assert_eq!(got, Err(ModelError::Other("bad_response".into())));
    let got = m
        .stream(&ep(&big, true), &request("s"), &mut Collect::default())
        .await;
    assert_eq!(got.unwrap_err(), ModelError::Outage);
}
