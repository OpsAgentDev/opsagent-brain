//! Turnstile on the three anonymous mail-sending endpoints: verified first, fail closed.
use opsagent_brain::config::Config;
use sea_orm::ConnectionTrait;
use serde_json::{json, Value};
use serial_test::serial;
use sha2::Digest;
use wiremock::{
    matchers::{body_string_contains, method, path},
    Mock, MockServer, ResponseTemplate,
};

use super::support::*;

const PATH: &str = "/turnstile/v0/siteverify";

/// Turnstile configured, pointed at `api`.
fn on(api: String) -> impl FnOnce(&mut Config) {
    move |c| {
        c.turnstile_secret_key = Some("sec_x".into());
        c.turnstile_api_base = api;
    }
}

/// Cloudflare answers `success` for the token `good` only.
async fn cloudflare() -> MockServer {
    let api = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(PATH))
        .and(body_string_contains("response=good"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": true})))
        .mount(&api)
        .await;
    Mock::given(method("POST"))
        .and(path(PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": false})))
        .mount(&api)
        .await;
    api
}

fn bodies() -> [(&'static str, Value); 3] {
    [
        ("/v1/auth/magic-link", json!({"email": "ann@visitor.io"})),
        (
            "/v1/contact",
            json!({"name": "Ann Visitor", "email": "ann@visitor.io", "topic": "general",
                   "message": "Hello there, a long enough message."}),
        ),
        ("/v1/waitlist", json!({"email": "ann@visitor.io"})),
    ]
}

fn with_token(mut body: Value, token: Option<&str>) -> Value {
    if let Some(t) = token {
        body["turnstile_token"] = json!(t);
    }
    body
}

/// Rate-limit keys these requests would write. Redis is shared with tests running in parallel, so
/// only this test's address is looked at (other tests write `ratelimit:org_create:*` and friends).
fn limit_keys(ctx: &TestApp) -> Vec<String> {
    let hash = opsagent_brain::tokens::hex(sha2::Sha256::digest("ann@visitor.io"));
    let mut c = redis_of(ctx).get_connection().unwrap();
    [
        "ratelimit:magic_link:*",
        "ratelimit:contact*",
        "ratelimit:waitlist*",
        "contact:*",
        "waitlist:*",
    ]
    .iter()
    .flat_map(|p| {
        opsagent_ledger::redis::cmd("KEYS")
            .arg(p)
            .query::<Vec<String>>(&mut c)
            .unwrap()
    })
    .filter(|k| !k.starts_with("ratelimit:magic_link:email:") || k.ends_with(&hash))
    .collect()
}

/// Earlier tests leave `contact:*`, `waitlist:*` and rate-limit keys behind in the shared Redis.
fn clear_limit_keys(ctx: &TestApp) {
    let mut c = redis_of(ctx).get_connection().unwrap();
    for p in ["ratelimit:*", "contact:*", "waitlist:*"] {
        let keys: Vec<String> = opsagent_ledger::redis::cmd("KEYS")
            .arg(p)
            .query(&mut c)
            .unwrap();
        for k in keys {
            opsagent_ledger::redis::cmd("DEL")
                .arg(k)
                .query::<i64>(&mut c)
                .unwrap();
        }
    }
}

async fn rows(ctx: &TestApp) -> i64 {
    let mut n = 0;
    for t in ["contact_messages", "waitlist_entries"] {
        let r = ctx
            .db
            .query_one_raw(sea_orm::Statement::from_string(
                sea_orm::DatabaseBackend::Postgres,
                format!("SELECT count(*) AS n FROM {t}"),
            ))
            .await
            .unwrap()
            .unwrap();
        n += r.try_get::<i64>("", "n").unwrap();
    }
    n
}

async fn assert_problem(res: axum_test::TestResponse, status: u16, code: &str) {
    assert_eq!(res.status_code(), status, "{}", res.text());
    assert_eq!(res.json::<Value>()["code"], code);
}

#[tokio::test]
#[serial]
async fn missing_or_bad_token_is_400_with_no_mail_row_or_rate_limit_key() {
    let api = cloudflare().await;
    serve_with(on(api.uri()), |req, ctx| async move {
        let mail = prepare(&ctx);
        clear_limit_keys(&ctx);
        for (url, body) in bodies() {
            for token in [None, Some("bad")] {
                let res = req.post(url).json(&with_token(body.clone(), token)).await;
                assert_problem(res, 400, "challenge_failed").await;
            }
        }
        // Checked before the address is parsed: an invalid address is no 202 shortcut.
        let res = req
            .post("/v1/auth/magic-link")
            .json(&json!({"email": "not-an-email"}))
            .await;
        assert_problem(res, 400, "challenge_failed").await;
        // Nor does the honeypot answer before the check.
        let mut b = bodies()[1].1.clone();
        b["website"] = json!("http://spam.example");
        let res = req.post("/v1/contact").json(&b).await;
        assert_problem(res, 400, "challenge_failed").await;

        assert!(mail.sent().is_empty());
        assert_eq!(rows(&ctx).await, 0);
        assert_eq!(limit_keys(&ctx), Vec::<String>::new());
    })
    .await;
}

#[tokio::test]
#[serial]
async fn valid_token_is_accepted_on_all_three() {
    let api = cloudflare().await;
    serve_with(on(api.uri()), |req, ctx| async move {
        let mail = prepare(&ctx);
        clear_limit_keys(&ctx);
        for (url, body) in bodies() {
            let res = req.post(url).json(&with_token(body, Some("good"))).await;
            assert_eq!(res.status_code(), 202, "{url}: {}", res.text());
        }
        assert!(mail
            .sent()
            .iter()
            .any(|m| m.subject.starts_with("Your OpsAgent sign-in code")));
        assert_eq!(rows(&ctx).await, 2);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn cloudflare_error_is_503_and_sends_nothing() {
    let api = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&api)
        .await;
    serve_with(on(api.uri()), |req, ctx| async move {
        let mail = prepare(&ctx);
        clear_limit_keys(&ctx);
        for (url, body) in bodies() {
            let res = req.post(url).json(&with_token(body, Some("good"))).await;
            assert_problem(res, 503, "challenge_unavailable").await;
        }
        assert!(mail.sent().is_empty());
        assert_eq!(rows(&ctx).await, 0);
        assert_eq!(limit_keys(&ctx), Vec::<String>::new());
    })
    .await;
}

#[tokio::test]
#[serial]
async fn unreachable_cloudflare_is_503() {
    // A closed port: the connection is refused.
    serve_with(on("http://127.0.0.1:9".into()), |req, _| async move {
        let res = req
            .post("/v1/waitlist")
            .json(&with_token(bodies()[2].1.clone(), Some("good")))
            .await;
        assert_problem(res, 503, "challenge_unavailable").await;
    })
    .await;
}

#[tokio::test]
#[serial]
async fn without_a_secret_outside_production_nothing_is_checked() {
    serve(|req, ctx| async move {
        let _ = prepare(&ctx);
        let res = req.post("/v1/waitlist").json(&bodies()[2].1).await;
        assert_eq!(res.status_code(), 202);
    })
    .await;
}
