//! `FakeModels`: a scripted `ModelProvider` for tests, and the `demo` script that
//! `OPSAGENT_MODEL_PROVIDER=fake` serves so the web e2e runs with no network.
use std::{collections::VecDeque, sync::Mutex};

use async_trait::async_trait;
use opsagent_core::model::{
    ModelError, ModelInfo, ModelProvider, ModelRequest, ModelTurn, Part, StopReason, TextSink,
    ToolCall, Usage,
};
use regex::Regex;
use serde_json::json;

use crate::config::{MODEL_CHAT, MODEL_ROUTINE};

/// One scripted model call.
#[derive(Debug, Clone)]
pub enum FakeStep {
    Text(String, Usage),
    Tools(Vec<ToolCall>, Usage),
    Fail(ModelError),
}

enum Script {
    Steps(Mutex<VecDeque<FakeStep>>),
    Demo,
}

pub struct FakeModels {
    script: Script,
    requests: Mutex<Vec<ModelRequest>>,
}

const DEMO_USAGE: Usage = Usage {
    input_tokens: 1000,
    output_tokens: 100,
    cache_read_tokens: 0,
    cache_write_tokens: 0,
};

const DEMO_EXPLANATION: &str = "What it means\nThis setting leaves the resource more exposed \
than it needs to be.\n\nWhy it matters here\nThe evidence shows the setting is in effect on \
this resource now.\n\nWhat to do\nOpen the resource in the provider console and change the \
setting, then run a scan to confirm.";

impl FakeModels {
    /// Answers each call with the next step, in order; a call past the last step fails with
    /// `fake_exhausted`.
    pub fn scripted(steps: Vec<FakeStep>) -> Self {
        Self::with(Script::Steps(Mutex::new(steps.into())))
    }

    /// With tools and no tool result yet: call `list_findings` with `{"limit": 1}`; after a
    /// tool result: cite its first finding; without tools: a fixed three-part explanation.
    pub fn demo() -> Self {
        Self::with(Script::Demo)
    }

    fn with(script: Script) -> Self {
        Self {
            script,
            requests: Mutex::new(Vec::new()),
        }
    }

    /// Every request received, in order.
    pub fn requests(&self) -> Vec<ModelRequest> {
        self.requests.lock().unwrap().clone()
    }

    fn next(&self, req: &ModelRequest) -> FakeStep {
        match &self.script {
            Script::Steps(q) => q
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| FakeStep::Fail(ModelError::Other("fake_exhausted".into()))),
            Script::Demo => demo_step(req),
        }
    }
}

fn demo_step(req: &ModelRequest) -> FakeStep {
    if req.tools.is_empty() {
        return FakeStep::Text(DEMO_EXPLANATION.into(), DEMO_USAGE);
    }
    let last_result = req
        .messages
        .iter()
        .flat_map(|m| &m.parts)
        .rev()
        .find_map(|p| match p {
            Part::ToolResult { content, .. } => Some(content.as_str()),
            _ => None,
        });
    let Some(result) = last_result else {
        let call = ToolCall {
            id: "call_demo_1".into(),
            name: "list_findings".into(),
            args: json!({"limit": 1}),
        };
        return FakeStep::Tools(vec![call], DEMO_USAGE);
    };
    let first = |key: &str| {
        let re = Regex::new(&format!(r#""{key}"\s*:\s*"([^"]+)""#)).unwrap();
        re.captures(result).map(|c| c[1].to_owned())
    };
    let text = match (first("id"), first("check_id")) {
        (Some(id), Some(check)) => {
            format!("Your newest finding is finding:{id} (check {check}).")
        }
        _ => "I don't know: the tools show no findings yet.".to_owned(),
    };
    FakeStep::Text(text, DEMO_USAGE)
}

#[async_trait]
impl ModelProvider for FakeModels {
    async fn stream(
        &self,
        _api_key: &str,
        req: &ModelRequest,
        sink: &mut dyn TextSink,
    ) -> Result<ModelTurn, ModelError> {
        self.requests.lock().unwrap().push(req.clone());
        let (text, tool_calls, usage, stop) = match self.next(req) {
            FakeStep::Text(t, u) => (t, vec![], u, StopReason::EndTurn),
            FakeStep::Tools(c, u) => (String::new(), c, u, StopReason::ToolUse),
            FakeStep::Fail(e) => return Err(e),
        };
        if !text.is_empty() {
            sink.delta(&text);
        }
        Ok(ModelTurn {
            text,
            tool_calls,
            usage,
            stop,
        })
    }

    async fn list_models(&self, _api_key: &str) -> Result<Vec<ModelInfo>, ModelError> {
        let info = |id: &str| ModelInfo {
            id: id.into(),
            tools: true,
        };
        Ok(vec![info(MODEL_ROUTINE), info(MODEL_CHAT)])
    }
}

#[cfg(test)]
mod tests {
    use opsagent_core::model::{ModelMessage, MsgRole, ToolDef};

    use super::*;

    #[derive(Default)]
    struct Sink(String);
    impl TextSink for Sink {
        fn delta(&mut self, t: &str) {
            self.0.push_str(t);
        }
    }

    fn req(tools: bool, parts: Vec<Part>) -> ModelRequest {
        let tool = ToolDef {
            name: "list_findings".into(),
            description: String::new(),
            input_schema: json!({}),
        };
        ModelRequest {
            model: MODEL_CHAT.into(),
            system: String::new(),
            messages: vec![ModelMessage {
                role: MsgRole::User,
                parts,
            }],
            tools: if tools { vec![tool] } else { vec![] },
            max_tokens: 100,
        }
    }

    #[tokio::test]
    async fn scripted_steps_run_in_order_and_requests_are_recorded() {
        let u = Usage {
            input_tokens: 7,
            ..Default::default()
        };
        let call = ToolCall {
            id: "c".into(),
            name: "get_scan".into(),
            args: json!({}),
        };
        let f = FakeModels::scripted(vec![
            FakeStep::Tools(vec![call.clone()], u),
            FakeStep::Text("done".into(), u),
            FakeStep::Fail(ModelError::Auth),
        ]);
        let r = req(true, vec![Part::Text("q".into())]);
        let mut sink = Sink::default();
        let t1 = f.stream("k", &r, &mut sink).await.unwrap();
        assert_eq!(
            (t1.tool_calls, t1.stop, t1.usage),
            (vec![call], StopReason::ToolUse, u)
        );
        let t2 = f.stream("k", &r, &mut sink).await.unwrap();
        assert_eq!((t2.text.as_str(), t2.stop), ("done", StopReason::EndTurn));
        assert_eq!(sink.0, "done");
        assert_eq!(f.stream("k", &r, &mut sink).await, Err(ModelError::Auth));
        let gone = f.stream("k", &r, &mut sink).await;
        assert_eq!(gone, Err(ModelError::Other("fake_exhausted".into())));
        assert_eq!(f.requests(), vec![r.clone(), r.clone(), r.clone(), r]);
    }

    #[tokio::test]
    async fn demo_calls_list_findings_then_cites_the_first_finding() {
        let f = FakeModels::demo();
        let mut sink = Sink::default();
        let first = f
            .stream(
                "k",
                &req(true, vec![Part::Text("newest?".into())]),
                &mut sink,
            )
            .await
            .unwrap();
        assert_eq!(first.tool_calls[0].name, "list_findings");
        assert_eq!(first.tool_calls[0].args, json!({"limit": 1}));
        let content = r#"<untrusted source="tool:list_findings">{"items":[{"connection_id":"c1","id":"f1","check_id":"no_mfa"},{"id":"f2","check_id":"x"}]}</untrusted>"#;
        let result = Part::ToolResult {
            call_id: "call_demo_1".into(),
            content: content.into(),
        };
        let second = f
            .stream("k", &req(true, vec![result]), &mut sink)
            .await
            .unwrap();
        assert_eq!(
            second.text,
            "Your newest finding is finding:f1 (check no_mfa)."
        );
        let explain = f.stream("k", &req(false, vec![]), &mut sink).await.unwrap();
        assert!(explain.text.starts_with("What it means"));
        assert!(
            explain.text.contains("Why it matters here") && explain.text.contains("What to do")
        );
        let ids: Vec<_> = f
            .list_models("k")
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.id)
            .collect();
        assert_eq!(ids, vec!["claude-haiku-5-5", "claude-sonnet-5-5"]);
    }
}
