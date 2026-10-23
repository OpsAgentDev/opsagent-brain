use loco_rs::prelude::*;
use opsagent_brain::models::_entities::{sessions, users};
use serde_json::{json, Value};
use serial_test::serial;

use super::support::*;

#[tokio::test]
#[serial]
async fn magic_link_creates_user_and_sends_one_mail() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        let res = req
            .post("/v1/auth/magic-link")
            .json(&json!({"email": "New@Example.com"}))
            .await;
        assert_eq!(res.status_code(), 202);
        assert_eq!(mail.sent().len(), 1);
        assert_eq!(mail.sent()[0].to, "new@example.com");
        assert!(last_link(&mail).starts_with(&format!("{WEB_ORIGIN}/auth/callback?token=")));
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
async fn magic_link_redeem_sets_cookie_and_is_single_use() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        req.post("/v1/auth/magic-link")
            .json(&json!({"email": "a@example.com"}))
            .await;
        let token = token_of(&last_link(&mail));

        // Wrong origin is refused and does not consume the link.
        let res = req
            .post("/v1/auth/magic-link/redeem")
            .add_header("Origin", "https://evil.example")
            .json(&json!({ "token": token }))
            .await;
        assert_eq!(res.status_code(), 403);
        assert_eq!(res.json::<Value>()["code"], "bad_origin");

        let res = redeem(&req, &token).await;
        assert_eq!(res.status_code(), 200);
        assert_eq!(
            res.json::<Value>()["redirect"],
            format!("{WEB_ORIGIN}/dashboard")
        );
        let cookie = res.header("set-cookie").to_str().unwrap().to_string();
        assert!(cookie.starts_with("opsagent_session="), "{cookie}");
        for attr in ["HttpOnly", "Secure", "SameSite=Lax"] {
            assert!(cookie.contains(attr), "{attr} missing in {cookie}");
        }

        let res = redeem(&req, &token).await;
        assert_eq!(res.status_code(), 410);
        assert_eq!(res.json::<Value>()["code"], "link_invalid");

        let post = |origin: Option<&str>, site: &str| {
            let mut r = req
                .post("/v1/auth/magic-link/redeem")
                .add_header("Sec-Fetch-Site", site);
            if let Some(o) = origin {
                r = r.add_header("Origin", o);
            }
            r.json(&json!({ "token": "nope" }))
        };
        // Present-but-different Origin loses even with Sec-Fetch-Site: same-site.
        let res = post(Some("https://evil.example"), "same-site").await;
        assert_eq!(res.status_code(), 403);
        // No Origin: same-origin passes (bad token -> 410, not 403); same-site does not.
        assert_eq!(post(None, "same-origin").await.status_code(), 410);
        assert_eq!(post(None, "same-site").await.status_code(), 403);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn authenticated_request_slides_session_expiry() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        sign_in(&req, &mail, "slide@example.com").await;
        let expiry = || async {
            sessions::Entity::find()
                .order_by_desc(sessions::Column::ExpiryDate)
                .one(&ctx.db)
                .await
                .unwrap()
                .unwrap()
                .expiry_date
        };
        let before = expiry().await;
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        assert_eq!(req.get("/v1/auth/me").await.status_code(), 200);
        assert!(expiry().await > before);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn csrf_exempt_get_works_without_token_and_me_needs_session() {
    serve(|req, ctx| async move {
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
    serve(|req, ctx| async move {
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
    serve(|req, _ctx| async move {
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

#[tokio::test]
#[serial]
async fn signed_out_session_is_not_resurrected() {
    serve(|mut req, ctx| async move {
        let mail = prepare(&ctx);
        let token = sign_in(&req, &mail, "gone@example.com").await;
        let sid = sessions::Entity::find()
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap()
            .id;
        let res = req
            .post("/v1/auth/sign-out")
            .add_header("X-CSRF-Token", &token)
            .await;
        assert_eq!(res.status_code(), 204);

        req.clear_cookies();
        let res = req
            .get("/v1/auth/me")
            .add_header("Cookie", format!("opsagent_session={sid}"))
            .await;
        assert_eq!(res.status_code(), 401);
        let rows = sessions::Entity::find_by_id(sid)
            .one(&ctx.db)
            .await
            .unwrap();
        assert!(rows.is_none());
    })
    .await;
}

#[tokio::test]
#[serial]
async fn cors_allows_only_the_web_origin_with_credentials() {
    serve(|req, _ctx| async move {
        let preflight = |origin: &'static str| {
            req.method(axum::http::Method::OPTIONS, "/v1/auth/csrf")
                .add_header("Origin", origin)
                .add_header("Access-Control-Request-Method", "POST")
                .add_header(
                    "Access-Control-Request-Headers",
                    "x-csrf-token,content-type",
                )
        };
        let ok = preflight(WEB_ORIGIN).await;
        let allow = |r: &axum_test::TestResponse, h: &str| {
            r.maybe_header(h).map(|v| v.to_str().unwrap().to_owned())
        };
        assert_eq!(
            allow(&ok, "access-control-allow-origin").as_deref(),
            Some(WEB_ORIGIN)
        );
        assert_eq!(
            allow(&ok, "access-control-allow-credentials").as_deref(),
            Some("true")
        );
        let bad = preflight("https://evil.example").await;
        // A fixed origin is always echoed; the browser rejects it for any other origin.
        assert_eq!(
            allow(&bad, "access-control-allow-origin").as_deref(),
            Some(WEB_ORIGIN)
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn magic_links_are_capped_per_address_without_revealing_it() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        for _ in 0..6 {
            let res = req
                .post("/v1/auth/magic-link")
                .json(&json!({"email": "busy@example.com"}))
                .await;
            assert_eq!(res.status_code(), 202);
        }
        assert_eq!(mail.sent().len(), 5);
        // Another address is unaffected.
        req.post("/v1/auth/magic-link")
            .json(&json!({"email": "calm@example.com"}))
            .await;
        assert_eq!(mail.sent().len(), 6);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn magic_links_are_capped_per_client_ip() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        // A fresh address per run: the counter lives in the shared Redis for an hour.
        let b = uuid::Uuid::new_v4().into_bytes();
        let ip = format!("10.{}.{}.{}", b[0], b[1], b[2]);
        for i in 0..31 {
            let res = req
                .post("/v1/auth/magic-link")
                .add_header("X-Forwarded-For", &ip)
                .json(&json!({ "email": format!("u{i}@example.com") }))
                .await;
            assert_eq!(res.status_code(), 202);
        }
        assert_eq!(mail.sent().len(), 30);
        // The rightmost entry (set by the trusted proxy) is the client; another one is unaffected.
        let other = format!("10.{}.{}.{}", b[3], b[4], b[5]);
        req.post("/v1/auth/magic-link")
            .add_header("X-Forwarded-For", format!("{ip}, {other}"))
            .json(&json!({"email": "other@example.com"}))
            .await;
        assert_eq!(mail.sent().len(), 31);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn magic_links_from_one_ipv6_64_share_one_cap() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        let b = uuid::Uuid::new_v4().into_bytes();
        let net = format!("2001:db8:{:x}:{:x}", b[0], b[1]);
        for i in 0..30 {
            let res = req
                .post("/v1/auth/magic-link")
                .add_header("X-Forwarded-For", format!("{net}::{:x}", i + 1))
                .json(&json!({ "email": format!("v{i}@example.com") }))
                .await;
            assert_eq!(res.status_code(), 202);
        }
        assert_eq!(mail.sent().len(), 30);
        // Another address in the same /64 is the same client: dropped, still 202.
        let res = req
            .post("/v1/auth/magic-link")
            .add_header("X-Forwarded-For", format!("{net}:ffff:ffff:ffff:ffff"))
            .json(&json!({"email": "v30@example.com"}))
            .await;
        assert_eq!(res.status_code(), 202);
        assert_eq!(mail.sent().len(), 30);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn concurrent_magic_links_for_one_address_send_exactly_the_cap() {
    use opsagent_brain::{actions::auth::MagicLinkInput, app, models::_entities::magic_links};
    serve(|_req, ctx| async move {
        let _mail = prepare(&ctx);
        let tasks: Vec<_> = (0..6)
            .map(|_| {
                let actions = app::actions(&ctx).unwrap();
                tokio::spawn(async move {
                    let input = MagicLinkInput {
                        email: "race@example.com".into(),
                        client_ip: None,
                    };
                    actions.auth.request_magic_link.run(input).await.unwrap();
                })
            })
            .collect();
        for t in tasks {
            t.await.unwrap();
        }
        let n = magic_links::Entity::find()
            .filter(magic_links::Column::Email.eq("race@example.com"))
            .count(&ctx.db)
            .await
            .unwrap();
        assert_eq!(n, 5);
    })
    .await;
}
