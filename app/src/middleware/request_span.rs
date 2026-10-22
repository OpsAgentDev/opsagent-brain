//! Replaces Loco's `logger` middleware, whose span records the full URI (`http.uri`) and so
//! leaks OAuth codes, states and path tokens into logs. This span names the route template
//! (`/v1/unsubscribe/{token}`) instead; status and latency come from the response event.
use axum::{
    extract::{MatchedPath, Request},
    Router as AxumRouter,
};
use loco_rs::{
    app::AppContext,
    controller::middleware::{request_id::LocoRequestId, MiddlewareLayer},
    Result,
};
use tower_http::trace::TraceLayer;

pub struct RequestSpan;

/// The span for one request: method, route template, request id. Never the raw URI or query.
pub fn span(req: &Request) -> tracing::Span {
    let ext = req.extensions();
    let route = ext
        .get::<MatchedPath>()
        .map_or("unmatched", MatchedPath::as_str);
    let request_id = ext
        .get::<LocoRequestId>()
        .map_or("req-id-none", |r| r.get());
    tracing::error_span!(
        "http-request",
        "http.method" = %req.method(),
        "http.route" = route,
        request_id = request_id,
    )
}

impl MiddlewareLayer for RequestSpan {
    fn name(&self) -> &'static str {
        "request_span"
    }

    fn config(&self) -> serde_json::Result<serde_json::Value> {
        Ok(serde_json::Value::Null)
    }

    fn apply(&self, app: AxumRouter<AppContext>) -> Result<AxumRouter<AppContext>> {
        Ok(app.layer(TraceLayer::new_for_http().make_span_with(span)))
    }
}

/// Loco's default stack with its `logger` swapped for `RequestSpan` in the same position.
pub fn stack(ctx: &AppContext) -> Vec<Box<dyn MiddlewareLayer>> {
    loco_rs::controller::middleware::default_middleware_stack(ctx)
        .into_iter()
        .map(|m| -> Box<dyn MiddlewareLayer> {
            if m.name() == "logger" {
                Box::new(RequestSpan)
            } else {
                m
            }
        })
        .collect()
}
