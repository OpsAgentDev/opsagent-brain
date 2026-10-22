use loco_rs::{prelude::*, testing::prelude::request_with_config};
use opsagent_brain::{app::App, models::_entities::users};
use serde_json::{json, Value};
use serial_test::serial;

use super::support::*;

#[tokio::test]
#[serial]
async fn magic_link_creates_user_and_sends_one_mail() {
    request_with_config::<App, _, _>(cookie_config(), |req, ctx| async move {
        let mail = prepare(&ctx);
        let res = req
            .post("/v1/auth/magic-link")
            .json(&json!({"email": "New@Example.com"}))
            .await;
        assert_eq!(res.status_code(), 202);
        assert_eq!(mail.sent().len(), 1);
        assert_eq!(mail.sent()[0].to, "new@example.com");
        let n = users::Entity::find().count(&ctx.db).await.unwrap();
        assert_eq!(n, 1);

        // Invalid address: still 202, no mail, no user.
        let res = req
            .post("/v1/auth/magic-link")
            .json(&json!({"email": "not-an-email"}))
            .await;
        assert_eq!(res.status_code(), 202);
        assert_eq!(mail.sent().len(), 1);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn magic_link_sets_cookie_redirects_and_is_single_use() {
    request_with_config::<App, _, _>(cookie_config(), |req, ctx| async move {
        let mail = prepare(&ctx);
        req.post("/v1/auth/magic-link")
            .json(&json!({"email": "a@example.com"}))
            .await;
        let path = path_of(&last_link(&mail));

        let res = req.get(&path).await;
        assert_eq!(res.status_code(), 302);
        let loc = res.header("location").to_str().unwrap().to_string();
        assert!(loc.ends_with("/dashboard"), "{loc}");
        let cookie = res.header("set-cookie").to_str().unwrap().to_string();
        assert!(cookie.starts_with("opsagent_session="), "{cookie}");
        for attr in ["HttpOnly", "Secure", "SameSite=Lax"] {
            assert!(cookie.contains(attr), "{attr} missing in {cookie}");
        }

        let res = req.get(&path).await;
        assert_eq!(res.status_code(), 410);
        assert_eq!(res.json::<Value>()["code"], "link_invalid");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn csrf_exempt_get_works_without_token_and_me_needs_session() {
    request_with_config::<App, _, _>(cookie_config(), |req, ctx| async move {
        let mail = prepare(&ctx);
        let res = req.get("/v1/auth/me").await;
        assert_eq!(res.status_code(), 401);
        assert_eq!(res.json::<Value>()["code"], "unauthenticated");

        sign_in(&req, &mail, "me@example.com").await;
        let res = req.get("/v1/auth/me").await; // no X-CSRF-Token
        assert_eq!(res.status_code(), 200);
        assert_eq!(res.json::<Value>()["email"], "me@example.com");
        assert_eq!(req.get("/healthz").await.status_code(), 200);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn sign_out_requires_csrf_and_ends_session() {
    request_with_config::<App, _, _>(cookie_config(), |req, ctx| async move {
        let mail = prepare(&ctx);
        let token = sign_in(&req, &mail, "out@example.com").await;
        assert_eq!(req.post("/v1/auth/sign-out").await.status_code(), 403);
        let res = req
            .post("/v1/auth/sign-out")
            .add_header("X-CSRF-Token", &token)
            .await;
        assert_eq!(res.status_code(), 204);
        assert_eq!(req.get("/v1/auth/me").await.status_code(), 401);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn github_start_returns_authorize_url_with_state_and_pkce() {
    std::env::set_var("GITHUB_CLIENT_ID", "cid");
    std::env::set_var("GITHUB_CLIENT_SECRET", "secret");
    request_with_config::<App, _, _>(cookie_config(), |req, _ctx| async move {
        let res = req.post("/v1/auth/sign-in/github/start").await;
        assert_eq!(res.status_code(), 200);
        let url = res.json::<Value>()["url"].as_str().unwrap().to_string();
        assert!(url.starts_with("https://github.com/login/oauth/authorize"));
        for p in ["state=", "code_challenge=", "client_id=cid"] {
            assert!(url.contains(p), "{p} missing in {url}");
        }
        // A callback with a forged state is rejected.
        let res = req
            .get("/v1/auth/sign-in/github/callback?code=x&state=forged")
            .await;
        assert_eq!(res.status_code(), 400);
        assert_eq!(res.json::<Value>()["code"], "oauth_state");
    })
    .await;
    std::env::remove_var("GITHUB_CLIENT_ID");
    std::env::remove_var("GITHUB_CLIENT_SECRET");
}
