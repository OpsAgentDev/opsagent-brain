//! Request id and the request span. The old framework's logger recorded the full URI (`http.uri`) and so
//! leaked OAuth codes, states and path tokens into logs. This span names the route template
//! (`/v1/unsubscribe/{token}`) instead; status and latency come from the response event.
use std::sync::OnceLock;

use axum::{
    extract::{MatchedPath, Request},
    http::HeaderValue,
    middleware::Next,
    response::Response,
};
use regex::Regex;

const X_REQUEST_ID: &str = "x-request-id";

/// The request's id: the sanitised `x-request-id` it came with, else a new UUID v4.
#[derive(Clone)]
pub struct RequestId(pub String);

/// The pre-switch rules, kept: only word characters, `-` and `@`, at most 255 of them.
fn sanitise(given: Option<&HeaderValue>) -> String {
    static STRIP: OnceLock<Regex> = OnceLock::new();
    let strip = STRIP.get_or_init(|| Regex::new(r"[^\w\-@]").expect("valid regex"));
    given
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            strip
                .replace_all(s, "")
                .chars()
                .take(255)
                .collect::<String>()
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
}

/// Sets the `RequestId` extension and echoes it on the response.
pub async fn request_id(mut req: Request, next: Next) -> Response {
    let id = sanitise(req.headers().get(X_REQUEST_ID));
    req.extensions_mut().insert(RequestId(id.clone()));
    let mut res = next.run(req).await;
    if let Ok(v) = HeaderValue::from_str(&id) {
        res.headers_mut().insert(X_REQUEST_ID, v);
    }
    res
}

/// The span for one request: method, route template, request id. Never the raw URI or query.
pub fn span(req: &Request) -> tracing::Span {
    let ext = req.extensions();
    let route = ext
        .get::<MatchedPath>()
        .map_or("unmatched", MatchedPath::as_str);
    let request_id = ext.get::<RequestId>().map_or("req-id-none", |r| &r.0);
    tracing::error_span!(
        "http-request",
        "http.method" = %req.method(),
        "http.route" = route,
        request_id = request_id,
    )
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::sanitise;

    #[test]
    fn request_id_is_sanitised_like_before() {
        let v = |s: &str| sanitise(Some(&HeaderValue::from_str(s).unwrap()));
        assert_eq!(v("foo-bar=baz"), "foo-barbaz");
        assert_eq!(v(&"x".repeat(1000)).len(), 255);
        assert_eq!(v("==========").len(), 36);
        assert_eq!(sanitise(None).len(), 36);
    }
}
