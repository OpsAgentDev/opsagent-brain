//! The HTTP middleware stack (app-shell.md): request id, request span, CSRF, session, CORS,
//! secure headers, timeout, catch-panic and the body limit. The old framework's `x-powered-by`
//! and etag are gone by ruling.
pub mod csrf;
pub mod org_scope;
pub mod request_span;
pub mod session;

use std::{any::Any, time::Duration};

use axum::{
    extract::{DefaultBodyLimit, Request, State},
    http::{header, HeaderName, HeaderValue, Method, StatusCode},
    middleware::{from_fn, from_fn_with_state, Next},
    response::{IntoResponse, Response},
    Router,
};
use tower_http::{
    catch_panic::CatchPanicLayer,
    cors::{Any as AnyOrigin, CorsLayer},
    set_header::SetResponseHeaderLayer,
    trace::{DefaultOnResponse, TraceLayer},
};
use tracing::Level;

use crate::{
    api_error::ApiError,
    config::AppEnv,
    error::{AppError, AppResult},
    state::AppState,
};

/// Today's value (the old framework's default).
const BODY_LIMIT: usize = 2_000_000;
/// MCP arguments (8 KB) plus the JSON-RPC envelope.
const PUBLIC_BODY_LIMIT: usize = 16_384;
const HSTS: &str = "max-age=31536000; includeSubDomains";

/// Wraps `routes`; each `.layer` wraps everything above it, so the last one meets the request
/// first.
pub fn stack(routes: Router, app: &AppState) -> AppResult<Router> {
    let c = &app.config;
    let routes = routes
        // The session must load before the CSRF guard runs.
        .layer(from_fn_with_state(app.clone(), csrf::guard))
        .layer(session::layer(app.db.clone(), c));
    shell(routes, app, cors_layer(&c.web_base_url)?, BODY_LIMIT)
}

/// The stack for OAuth, discovery and MCP: no session or CSRF (bearer tokens only), any origin
/// without credentials, and the small body limit.
pub fn public_stack(routes: Router, app: &AppState) -> AppResult<Router> {
    let cors = CorsLayer::new()
        .allow_origin(AnyOrigin)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            HeaderName::from_static("mcp-protocol-version"),
            HeaderName::from_static("mcp-method"),
            HeaderName::from_static("mcp-name"),
        ])
        .expose_headers([header::WWW_AUTHENTICATE]);
    shell(routes, app, cors, PUBLIC_BODY_LIMIT)
}

/// The layers both stacks share.
fn shell(routes: Router, app: &AppState, cors: CorsLayer, body_limit: usize) -> AppResult<Router> {
    let c = &app.config;
    // The response event (INFO) carries `status` and `latency`, inside the span.
    let trace = TraceLayer::new_for_http()
        .make_span_with(request_span::span)
        .on_response(DefaultOnResponse::new().level(Level::INFO));
    let hsts = (c.env == AppEnv::Production).then_some(HeaderValue::from_static(HSTS));
    let set = |name, value: &'static str| {
        SetResponseHeaderLayer::overriding(name, HeaderValue::from_static(value))
    };
    let timeout_after = Duration::from_secs(c.request_timeout_secs);
    Ok(routes
        .layer(from_fn_with_state(timeout_after, timeout))
        .layer(CatchPanicLayer::custom(panic_problem))
        .layer(DefaultBodyLimit::max(body_limit))
        // Outside every layer that can answer on its own (CSRF, session, timeout, panic), so
        // those responses reach the browser with CORS and secure headers and are logged once.
        .layer(cors)
        .layer(set(header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
        .layer(set(header::X_FRAME_OPTIONS, "DENY"))
        .layer(set(header::REFERRER_POLICY, "no-referrer"))
        .layer(SetResponseHeaderLayer::overriding(
            header::STRICT_TRANSPORT_SECURITY,
            move |_: &Response| hsts.clone(),
        ))
        // Just inside the request id, which the span reads.
        .layer(trace)
        .layer(from_fn(request_span::request_id)))
}

/// The web origin only, with credentials (the session cookie); headers and methods must be
/// listed explicitly because credentials forbid wildcards.
fn cors_layer(web_base_url: &str) -> AppResult<CorsLayer> {
    let origin: HeaderValue = web_base_url
        .trim_end_matches('/')
        .parse()
        .map_err(|_| AppError::Internal("WEB_BASE_URL is not a valid origin".into()))?;
    Ok(CorsLayer::new()
        .allow_origin(origin)
        .allow_credentials(true)
        .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE])
        .allow_headers([
            header::CONTENT_TYPE,
            HeaderName::from_static("x-csrf-token"),
        ]))
}

async fn timeout(State(after): State<Duration>, req: Request, next: Next) -> Response {
    match tokio::time::timeout(after, next.run(req)).await {
        Ok(res) => res,
        Err(_) => ApiError::new(
            StatusCode::GATEWAY_TIMEOUT,
            "timeout",
            "The request took too long.",
        )
        .into_response(),
    }
}

/// Logs the panic message (as before the switch) and answers a 500 `internal` problem.
fn panic_problem(err: Box<dyn Any + Send + 'static>) -> Response {
    let msg = err
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| err.downcast_ref::<&str>().copied())
        .unwrap_or("no error details");
    ApiError::internal(format!("panic: {msg}")).into_response()
}
