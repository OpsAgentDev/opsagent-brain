//! The HTTP middleware stack (app-shell.md): request id, request span, CSRF, session, CORS,
//! secure headers, timeout, catch-panic and the body limit. Loco's `x-powered-by` and etag are
//! gone by ruling.
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
    cors::CorsLayer,
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

/// Today's value (Loco's default).
const BODY_LIMIT: usize = 2_000_000;
const HSTS: &str = "max-age=31536000; includeSubDomains";

/// Wraps `routes`; each `.layer` wraps everything above it, so the last one meets the request
/// first. Secure headers sit outside timeout and catch-panic so their 504 and 500 carry them too.
pub fn stack(routes: Router, app: &AppState) -> AppResult<Router> {
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
        .layer(trace)
        // The session must load before the CSRF guard runs, and CORS wraps both so their
        // error responses still reach the browser.
        .layer(from_fn_with_state(app.clone(), csrf::guard))
        .layer(session::layer(app.db.clone(), c))
        .layer(cors_layer(&c.web_base_url)?)
        .layer(from_fn_with_state(timeout_after, timeout))
        .layer(CatchPanicLayer::custom(panic_problem))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(set(header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
        .layer(set(header::X_FRAME_OPTIONS, "DENY"))
        .layer(set(header::REFERRER_POLICY, "no-referrer"))
        .layer(SetResponseHeaderLayer::overriding(
            header::STRICT_TRANSPORT_SECURITY,
            move |_: &Response| hsts.clone(),
        ))
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

/// Logs the panic message (as Loco did) and answers a 500 `internal` problem.
fn panic_problem(err: Box<dyn Any + Send + 'static>) -> Response {
    let msg = err
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| err.downcast_ref::<&str>().copied())
        .unwrap_or("no error details");
    ApiError::internal(format!("panic: {msg}")).into_response()
}
