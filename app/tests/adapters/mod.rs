mod anthropic;
mod openai;
mod slack;
mod stripe;

use opsagent_core::model::{ModelError, TextSink};
use serde_json::{json, Value};

/// Collects the streamed deltas.
#[derive(Default)]
pub struct Collect(pub Vec<String>);

impl TextSink for Collect {
    fn delta(&mut self, text: &str) {
        self.0.push(text.to_owned());
    }
}

/// An SSE body of `event:`/`data:` frames.
pub fn sse_body(events: &[(&str, Value)]) -> String {
    events
        .iter()
        .map(|(e, d)| format!("event: {e}\ndata: {d}\n\n"))
        .collect()
}

/// (status, body, error) shared by both adapters.
pub fn status_cases() -> Vec<(u16, Value, ModelError)> {
    let err = |t: &str| json!({"error": {"type": t, "message": "provider text"}});
    vec![
        (401, err("authentication_error"), ModelError::Auth),
        (403, err("permission_error"), ModelError::Auth),
        (429, err("rate_limit_error"), ModelError::RateLimited),
        (404, err("not_found_error"), ModelError::ModelGone),
        (500, err("api_error"), ModelError::Outage),
        (529, err("overloaded_error"), ModelError::RateLimited),
        (503, err("overloaded_error"), ModelError::RateLimited),
        (
            400,
            err("invalid_request_error"),
            ModelError::Other("http_400".into()),
        ),
    ]
}
