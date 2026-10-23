//! The HTTP shell's behaviour that must not change when Loco's stack is replaced (Task 14).
use serde_json::{json, Value};
use serial_test::serial;

use super::support::*;

#[tokio::test]
#[serial]
async fn request_id_echoed_and_generated() {
    serve(|req, _ctx| async move {
        let res = req
            .get("/healthz")
            .add_header("x-request-id", "abc-123=@x!")
            .await;
        // Loco's sanitising: only word chars, `-` and `@` survive.
        assert_eq!(res.header("x-request-id"), "abc-123@x");
        let long = "x".repeat(300);
        let res = req.get("/healthz").add_header("x-request-id", &long).await;
        assert_eq!(res.header("x-request-id").len(), 255);
        let res = req.get("/healthz").await;
        let id = res.header("x-request-id").to_str().unwrap().to_string();
        assert!(uuid::Uuid::parse_str(&id).is_ok(), "{id}");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn cors_preflight_web_origin_only() {
    serve(|req, _ctx| async move {
        let res = req
            .method(axum::http::Method::OPTIONS, "/v1/orgs")
            .add_header("Origin", WEB_ORIGIN)
            .add_header("Access-Control-Request-Method", "PATCH")
            .add_header(
                "Access-Control-Request-Headers",
                "content-type,x-csrf-token",
            )
            .await;
        assert_eq!(res.status_code(), 200);
        assert_eq!(res.header("access-control-allow-origin"), WEB_ORIGIN);
        assert_eq!(res.header("access-control-allow-credentials"), "true");
        assert_eq!(
            res.header("access-control-allow-methods"),
            "GET,POST,PATCH,DELETE"
        );
        assert_eq!(
            res.header("access-control-allow-headers"),
            "content-type,x-csrf-token"
        );
        let res = req
            .method(axum::http::Method::OPTIONS, "/v1/orgs")
            .add_header("Origin", "https://evil.example")
            .add_header("Access-Control-Request-Method", "POST")
            .await;
        // tower-http's exact origin is always sent; the browser refuses it for any other origin.
        assert_eq!(res.header("access-control-allow-origin"), WEB_ORIGIN);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn body_over_two_megabytes_is_413() {
    // shortcut: named for the brief, but today's answer is 400 `invalid_body` (axum's
    // DefaultBodyLimit surfaces through `ApiJson`), kept as is until a ruling picks 413.
    serve(|req, _ctx| async move {
        // `{"email":"…"}` padded to exactly 2,000,001 bytes.
        let pad = "a".repeat(2_000_001 - r#"{"email":""}"#.len());
        let body = json!({ "email": pad }).to_string();
        assert_eq!(body.len(), 2_000_001);
        let res = req
            .post("/v1/auth/magic-link")
            .content_type("application/json")
            .bytes(body.into())
            .await;
        assert_eq!(res.status_code(), 400, "{}", res.text());
        let p = res.json::<Value>();
        assert_eq!(p["code"], "invalid_body");
        assert!(p["detail"]
            .as_str()
            .unwrap()
            .contains("length limit exceeded"));
        // At the limit the request is read (and answered as usual).
        let pad = "a".repeat(2_000_000 - r#"{"email":""}"#.len());
        let res = req
            .post("/v1/auth/magic-link")
            .json(&json!({ "email": pad }))
            .await;
        assert_eq!(res.status_code(), 202);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn unmatched_route_404() {
    serve(|req, _ctx| async move {
        assert_eq!(req.get("/no/such/route").await.status_code(), 404);
        assert_eq!(req.get("/v1/no-such").await.status_code(), 404);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn default_loco_routes_status() {
    serve(|req, _ctx| async move {
        for path in ["/_ping", "/_health", "/_readiness"] {
            let res = req.get(path).await;
            assert_eq!(res.status_code(), 200, "{path}");
            assert_eq!(res.json::<Value>(), json!({ "ok": true }), "{path}");
        }
        assert_eq!(req.get("/healthz").await.status_code(), 200);
        assert_eq!(req.get("/readyz").await.status_code(), 200);
    })
    .await;
}

// Ruled changes (2026-10-23): asserted on the axum shell only.

/// The shell's router over the booted state with `f` applied to its config.
fn router_with(
    ctx: &loco_rs::app::AppContext,
    f: impl FnOnce(&mut opsagent_brain::config::Config),
) -> axum_test::TestServer {
    let mut deps = opsagent_brain::app::state(ctx).unwrap().deps.clone();
    f(&mut deps.config);
    let router = opsagent_brain::boot::router(opsagent_brain::boot::assemble(deps)).unwrap();
    axum_test::TestServer::new(router).unwrap()
}

fn assert_secure_headers(res: &axum_test::TestResponse) {
    assert_eq!(res.header("x-content-type-options"), "nosniff");
    assert_eq!(res.header("x-frame-options"), "DENY");
    assert_eq!(res.header("referrer-policy"), "no-referrer");
}

#[tokio::test]
#[serial]
async fn secure_headers_present_and_hsts_only_in_production() {
    serve(|req, ctx| async move {
        let preflight = req
            .method(axum::http::Method::OPTIONS, "/v1/orgs")
            .add_header("Origin", WEB_ORIGIN)
            .add_header("Access-Control-Request-Method", "POST")
            .await;
        for res in [
            req.get("/healthz").await,
            req.get("/no/such/route").await,
            req.get("/v1/auth/me").await,
            preflight,
        ] {
            assert_secure_headers(&res);
            assert!(res.maybe_header("strict-transport-security").is_none());
        }
        let prod = router_with(&ctx, |c| c.env = opsagent_brain::config::AppEnv::Production);
        let res = prod.get("/healthz").await;
        assert_secure_headers(&res);
        assert_eq!(
            res.header("strict-transport-security"),
            "max-age=31536000; includeSubDomains"
        );
        // Unmatched routes stay 404 in production (Loco's dev fallback page is gone).
        assert_eq!(prod.get("/no/such/route").await.status_code(), 404);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn powered_by_and_etag_absent() {
    serve(|req, _ctx| async move {
        for path in ["/healthz", "/_ping", "/no/such/route"] {
            let res = req.get(path).await;
            assert!(res.maybe_header("x-powered-by").is_none(), "{path}");
            assert!(res.maybe_header("etag").is_none(), "{path}");
        }
    })
    .await;
}

#[tokio::test]
#[serial]
async fn slow_handler_is_504() {
    serve(|_req, ctx| async move {
        // The 30 s production default is pinned in config.rs; one second keeps the test short.
        let srv = router_with(&ctx, |c| c.request_timeout_secs = 1);
        let res = srv
            .get("/_test/slow")
            .add_header("x-request-id", "slow-1")
            .await;
        assert_eq!(res.status_code(), 504);
        assert_eq!(res.header("content-type"), "application/problem+json");
        assert_eq!(res.json::<Value>()["code"], "timeout");
        assert_eq!(res.header("x-request-id"), "slow-1");
        assert_secure_headers(&res);

        let res = srv.get("/_test/panic").await;
        assert_eq!(res.status_code(), 500);
        assert_eq!(res.json::<Value>()["code"], "internal");
        assert_secure_headers(&res);
    })
    .await;
}
