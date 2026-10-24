use std::collections::HashMap;

use axum_test::TestServer;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use opsagent_core::oauth::{ClientKind, OAuthClient};
use serde_json::{json, Value};
use serial_test::serial;
use sha2::{Digest, Sha256};

use super::support::*;

pub const BASE: &str = "http://localhost:5150";
pub const CLIENT: &str = "dyn-client";
pub const REDIRECT: &str = "https://app.example/cb";
pub const VERIFIER: &str = "verifier-verifier-verifier-verifier-verifier-0123";

pub fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// A dynamic client registered for `REDIRECT` and a loopback URI.
pub async fn client(app: &TestApp) {
    let c = OAuthClient {
        client_id: CLIENT.into(),
        kind: ClientKind::Dynamic,
        name: "Demo client".into(),
        redirect_uris: vec![REDIRECT.into(), "http://127.0.0.1:53121/callback".into()],
        document_fetched_at: None,
        document_cache_until: None,
        last_used_at: None,
        expires_at: Some(chrono::Utc::now() + chrono::Duration::days(90)),
    };
    app.state.uow.oauth().upsert_client(&c).await.unwrap();
}

pub fn params(redirect_uri: &str) -> Vec<(&'static str, String)> {
    vec![
        ("response_type", "code".into()),
        ("client_id", CLIENT.into()),
        ("redirect_uri", redirect_uri.into()),
        ("code_challenge", challenge(VERIFIER)),
        ("code_challenge_method", "S256".into()),
        ("state", "st-1".into()),
    ]
}

fn with(
    mut p: Vec<(&'static str, String)>,
    k: &'static str,
    v: &str,
) -> Vec<(&'static str, String)> {
    p.retain(|(key, _)| *key != k);
    p.push((k, v.into()));
    p
}

pub async fn authorize(req: &TestServer, p: &[(&'static str, String)]) -> axum_test::TestResponse {
    req.get("/oauth/authorize").add_query_params(p).await
}

pub fn query_of(url: &str) -> HashMap<String, String> {
    reqwest::Url::parse(url)
        .unwrap()
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// A consent request id from a successful authorize.
pub async fn request_id(req: &TestServer, redirect_uri: &str) -> String {
    let res = authorize(req, &params(redirect_uri)).await;
    assert_eq!(res.status_code(), 302, "{}", res.text());
    query_of(res.header("location").to_str().unwrap())["request_id"].clone()
}

pub async fn decide(
    req: &TestServer,
    csrf: &str,
    id: &str,
    body: Value,
) -> axum_test::TestResponse {
    req.post(&format!("/v1/oauth/consent/{id}"))
        .add_header("X-CSRF-Token", csrf)
        .json(&body)
        .await
}

#[tokio::test]
#[serial]
async fn authorize_redirects_to_web_consent() {
    serve(|req, app| async move {
        client(&app).await;
        let res = authorize(&req, &params(REDIRECT)).await;
        assert_eq!(res.status_code(), 302);
        let loc = res.header("location").to_str().unwrap().to_owned();
        assert!(
            loc.starts_with(&format!("{WEB_ORIGIN}/oauth/consent?request_id=")),
            "{loc}"
        );
        let id: uuid::Uuid = query_of(&loc)["request_id"].parse().unwrap();
        let stored = app.state.uow.oauth().consent(id).await.unwrap().unwrap();
        assert_eq!(stored.scope, "opsagent.read");
        assert_eq!(stored.resource, format!("{BASE}/mcp"));
        assert_eq!(stored.state.as_deref(), Some("st-1"));
    })
    .await;
}

#[tokio::test]
#[serial]
async fn authorize_plain_pkce_redirects_with_invalid_request() {
    serve(|req, app| async move {
        client(&app).await;
        let res = authorize(
            &req,
            &with(params(REDIRECT), "code_challenge_method", "plain"),
        )
        .await;
        assert_eq!(res.status_code(), 302);
        let loc = res.header("location").to_str().unwrap().to_owned();
        assert!(loc.starts_with(REDIRECT), "{loc}");
        let q = query_of(&loc);
        assert_eq!(q["error"], "invalid_request");
        assert_eq!(q["state"], "st-1");
        assert_eq!(q["iss"], BASE);
        let res = authorize(&req, &with(params(REDIRECT), "scope", "opsagent.write")).await;
        assert_eq!(
            query_of(res.header("location").to_str().unwrap())["error"],
            "invalid_scope"
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn authorize_unknown_redirect_uri_does_not_redirect() {
    serve(|req, app| async move {
        client(&app).await;
        for p in [
            params("https://evil.example/cb"),
            with(params(REDIRECT), "client_id", "nobody"),
        ] {
            let res = authorize(&req, &p).await;
            assert!(res.status_code().is_client_error(), "{}", res.status_code());
            assert!(res.headers().get("location").is_none());
            assert!(res.json::<Value>()["error"].is_string());
        }
        let res = authorize(&req, &params("https://evil.example/cb")).await;
        assert_eq!(res.status_code(), 400);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn authorize_wrong_resource_is_invalid_target() {
    serve(|req, app| async move {
        client(&app).await;
        let p = with(params(REDIRECT), "resource", "https://other.example/mcp");
        let res = authorize(&req, &p).await;
        assert_eq!(res.status_code(), 302);
        let q = query_of(res.header("location").to_str().unwrap());
        assert_eq!(q["error"], "invalid_target");
        let p = with(params(REDIRECT), "resource", &format!("{BASE}/mcp/"));
        let res = authorize(&req, &p).await;
        assert!(query_of(res.header("location").to_str().unwrap()).contains_key("request_id"));
    })
    .await;
}

#[tokio::test]
#[serial]
async fn authorize_rate_limited_per_ip() {
    serve(|req, _| async move {
        let hit = || {
            req.get("/oauth/authorize")
                .add_header("x-forwarded-for", "198.51.100.9")
        };
        for _ in 0..120 {
            assert_eq!(hit().await.status_code(), 400);
        }
        let res = hit().await;
        assert_eq!(res.status_code(), 429);
        assert!(res.headers().get("location").is_none());
        assert_eq!(res.json::<Value>()["error"], "slow_down");
        let other = req
            .get("/oauth/authorize")
            .add_header("x-forwarded-for", "198.51.100.10")
            .await;
        assert_eq!(other.status_code(), 400);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn consent_view_flags_loopback() {
    serve(|req, app| async move {
        let mail = prepare(&app);
        let csrf = sign_in(&req, &mail, "owner@example.com").await;
        let org = create_org(&req, &csrf, "Acme").await;
        client(&app).await;
        let id = request_id(&req, "http://127.0.0.1:60000/callback").await;
        let res = req.get(&format!("/v1/oauth/consent/{id}")).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        assert_eq!(
            res.json::<Value>(),
            json!({
                "client_name": "Demo client",
                "redirect_uri": "http://127.0.0.1:60000/callback",
                "verified": false,
                "loopback": true,
                "organisations": [{"slug": slug(&org), "name": "Acme"}],
            })
        );
        let id = request_id(&req, REDIRECT).await;
        let v: Value = req.get(&format!("/v1/oauth/consent/{id}")).await.json();
        assert_eq!(v["loopback"], false);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn approve_returns_code_state_iss() {
    serve(|req, app| async move {
        let mail = prepare(&app);
        let csrf = sign_in(&req, &mail, "owner@example.com").await;
        let org = create_org(&req, &csrf, "Acme").await;
        client(&app).await;
        let id = request_id(&req, REDIRECT).await;
        let res = decide(&req, &csrf, &id, json!({"organisation": slug(&org)})).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        let to = res.json::<Value>()["redirect_to"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(to.starts_with(REDIRECT), "{to}");
        let q = query_of(&to);
        assert!(q["code"].len() > 20);
        assert_eq!((q["state"].as_str(), q["iss"].as_str()), ("st-1", BASE));
        let stored = app
            .state
            .uow
            .oauth()
            .consent(id.parse().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_ne!(stored.code_hash.as_deref(), Some(q["code"].as_str()));
        assert!(stored.organisation_id.is_some());
    })
    .await;
}

#[tokio::test]
#[serial]
async fn deny_returns_access_denied() {
    serve(|req, app| async move {
        let mail = prepare(&app);
        let csrf = sign_in(&req, &mail, "owner@example.com").await;
        client(&app).await;
        let id = request_id(&req, REDIRECT).await;
        let res = decide(&req, &csrf, &id, json!({"deny": true})).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        let q = query_of(res.json::<Value>()["redirect_to"].as_str().unwrap());
        assert_eq!(q["error"], "access_denied");
        assert_eq!((q["state"].as_str(), q["iss"].as_str()), ("st-1", BASE));
        assert!(!q.contains_key("code"));
    })
    .await;
}

#[tokio::test]
#[serial]
async fn approve_for_non_member_org_is_404() {
    serve(|req, app| async move {
        let mail = prepare(&app);
        let csrf = sign_in(&req, &mail, "other@example.com").await;
        let theirs = create_org(&req, &csrf, "Theirs").await;
        sign_out(&req, &csrf).await;
        let csrf = sign_in(&req, &mail, "owner@example.com").await;
        client(&app).await;
        let id = request_id(&req, REDIRECT).await;
        let res = decide(&req, &csrf, &id, json!({"organisation": slug(&theirs)})).await;
        assert_eq!(res.status_code(), 404);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn consent_twice_is_gone() {
    serve(|req, app| async move {
        let mail = prepare(&app);
        let csrf = sign_in(&req, &mail, "owner@example.com").await;
        let org = create_org(&req, &csrf, "Acme").await;
        client(&app).await;
        let id = request_id(&req, REDIRECT).await;
        let body = json!({"organisation": slug(&org)});
        assert_eq!(
            decide(&req, &csrf, &id, body.clone()).await.status_code(),
            200
        );
        let again = decide(&req, &csrf, &id, body).await;
        assert_eq!(again.status_code(), 410);
        assert_eq!(again.json::<Value>()["code"], "consent_expired");
        let view = req.get(&format!("/v1/oauth/consent/{id}")).await;
        assert_eq!(view.status_code(), 410);
        let unknown = req
            .get(&format!("/v1/oauth/consent/{}", uuid::Uuid::new_v4()))
            .await;
        assert_eq!(unknown.status_code(), 410);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn consent_post_requires_csrf() {
    serve(|req, app| async move {
        let mail = prepare(&app);
        let csrf = sign_in(&req, &mail, "owner@example.com").await;
        let org = create_org(&req, &csrf, "Acme").await;
        client(&app).await;
        let id = request_id(&req, REDIRECT).await;
        let res = req
            .post(&format!("/v1/oauth/consent/{id}"))
            .json(&json!({"organisation": slug(&org)}))
            .await;
        assert_eq!(res.status_code(), 403);
        assert_eq!(res.json::<Value>()["code"], "csrf");
    })
    .await;
}
