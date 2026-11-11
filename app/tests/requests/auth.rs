use axum_test::TestServer;
use opsagent_brain::models::_entities::{sessions, users};
use sea_orm::{entity::prelude::*, QueryOrder};
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
async fn verify_code_sets_cookie_and_honours_origin() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        req.post("/v1/auth/magic-link")
            .json(&json!({"email": "Code@Example.com"}))
            .await;
        let m = mail.sent().pop().unwrap();
        let code = m.subject.rsplit(' ').next().unwrap().to_string();
        let verify = |origin: &'static str, code: &str| {
            req.post("/v1/auth/magic-link/verify")
                .add_header("Origin", origin)
                .json(&json!({ "email": "code@example.com", "code": code }))
        };

        let res = verify("https://evil.example", &code).await;
        assert_eq!(res.status_code(), 403);

        let res = verify(WEB_ORIGIN, &code).await;
        assert_eq!(res.status_code(), 200);
        assert!(res.json::<Value>()["redirect"]
            .as_str()
            .unwrap()
            .ends_with("/dashboard"));
        let cookie = res.header("set-cookie").to_str().unwrap().to_string();
        assert!(cookie.starts_with("opsagent_session="), "{cookie}");

        let res = verify(WEB_ORIGIN, &code).await;
        assert_eq!(res.status_code(), 410);
        assert_eq!(res.json::<Value>()["code"], "code_invalid");
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
async fn deleting_the_account_needs_the_email_and_signs_out() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        let token = sign_in(&req, &mail, "gone@example.com").await;
        let del = |confirm: &'static str| {
            req.delete("/v1/auth/me")
                .add_header("X-CSRF-Token", &token)
                .json(&json!({ "confirm": confirm }))
        };
        assert_eq!(del("someone@example.com").await.status_code(), 422);
        assert_eq!(del("Gone@Example.com").await.status_code(), 204);
        assert_eq!(req.get("/v1/auth/me").await.status_code(), 401);
        let row = users::Entity::find()
            .filter(users::Column::DeletedAt.is_not_null())
            .one(&ctx.db)
            .await
            .unwrap()
            .expect("erased row kept");
        assert!(row.email.ends_with("@deleted.invalid"), "{}", row.email);
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
        assert_eq!(res.status_code(), 302);
        assert_eq!(
            location(&res),
            format!("{WEB_ORIGIN}/sign-in?error=oauth_state")
        );
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
    use opsagent_brain::{actions::auth::MagicLinkInput, models::_entities::magic_links};
    serve(|_req, ctx| async move {
        let _mail = prepare(&ctx);
        let tasks: Vec<_> = (0..6)
            .map(|_| {
                let actions = actions(&ctx).unwrap();
                tokio::spawn(async move {
                    let input = MagicLinkInput {
                        email: "race@example.com".into(),
                        client_ip: None,
                        return_to: None,
                        name: None,
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

const CONSENT: &str = "/oauth/consent?request_id=0192f3a4-7b1c-7d2e-8f3a-4b5c6d7e8f90";

/// Requests a link with `return_to` and redeems it: the `redirect` the web page follows.
async fn redirect_after(req: &TestServer, ctx: &TestApp, return_to: &str) -> String {
    let mail = prepare(ctx);
    let res = req
        .post("/v1/auth/magic-link")
        .json(&json!({ "email": "rt@example.com", "return_to": return_to }))
        .await;
    assert_eq!(res.status_code(), 202);
    let res = redeem(req, &token_of(&last_link(&mail))).await;
    assert_eq!(res.status_code(), 200);
    res.json::<Value>()["redirect"].as_str().unwrap().to_owned()
}

#[tokio::test]
#[serial]
async fn magic_link_return_to_round_trips() {
    serve(|req, ctx| async move {
        let got = redirect_after(&req, &ctx, CONSENT).await;
        assert_eq!(got, format!("{WEB_ORIGIN}{CONSENT}"));
    })
    .await;
}

#[tokio::test]
#[serial]
async fn magic_link_bad_return_to_falls_back_to_dashboard() {
    serve(|mut req, ctx| async move {
        for bad in ["//evil.example", "https://evil.example/x", "/dashboard"] {
            let got = redirect_after(&req, &ctx, bad).await;
            assert_eq!(got, format!("{WEB_ORIGIN}/dashboard"), "{bad}");
            req.clear_cookies();
        }
    })
    .await;
}

/// The callback needs GitHub itself, so this covers the start half (the validated value is
/// kept beside the state) and the callback's state check; `landing` is unit tested.
#[tokio::test]
#[serial]
async fn github_return_to_round_trips() {
    std::env::set_var("GITHUB_CLIENT_ID", "cid");
    std::env::set_var("GITHUB_CLIENT_SECRET", "secret");
    serve(|req, _ctx| async move {
        for to in [CONSENT, "//evil.example"] {
            let res = req
                .post("/v1/auth/sign-in/github/start")
                .add_query_param("return_to", to)
                .await;
            assert_eq!(res.status_code(), 200, "{to}");
        }
        let res = req
            .get("/v1/auth/sign-in/github/callback?code=x&state=forged")
            .await;
        assert_eq!(res.status_code(), 302);
        assert!(location(&res).contains("error=oauth_state"));
    })
    .await;
    std::env::remove_var("GITHUB_CLIENT_ID");
    std::env::remove_var("GITHUB_CLIENT_SECRET");
}

fn location(res: &axum_test::TestResponse) -> String {
    res.header("location").to_str().unwrap().to_owned()
}

#[tokio::test]
#[serial]
async fn google_start_is_503_when_unconfigured() {
    serve(|req, _ctx| async move {
        let res = req.post("/v1/auth/sign-in/google/start").await;
        assert_eq!(res.status_code(), 503);
        assert_eq!(res.json::<Value>()["code"], "google_not_configured");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn google_start_returns_google_url_with_pkce() {
    std::env::set_var("GOOGLE_CLIENT_ID", "gid");
    std::env::set_var("GOOGLE_CLIENT_SECRET", "secret");
    serve(|req, _ctx| async move {
        let res = req.post("/v1/auth/sign-in/google/start").await;
        assert_eq!(res.status_code(), 200);
        let url = res.json::<Value>()["url"].as_str().unwrap().to_string();
        assert!(
            url.starts_with("https://accounts.google.com/o/oauth2/v2/auth"),
            "{url}"
        );
        for p in [
            "state=",
            "code_challenge=",
            "client_id=gid",
            "scope=openid+email+profile",
        ] {
            assert!(url.contains(p), "{p} missing in {url}");
        }
    })
    .await;
    std::env::remove_var("GOOGLE_CLIENT_ID");
    std::env::remove_var("GOOGLE_CLIENT_SECRET");
}

#[tokio::test]
#[serial]
async fn google_callback_with_bad_state_redirects_to_sign_in_error() {
    std::env::set_var("GOOGLE_CLIENT_ID", "gid");
    std::env::set_var("GOOGLE_CLIENT_SECRET", "secret");
    serve(|req, _ctx| async move {
        // No pending sign-in at all.
        let res = req
            .get("/v1/auth/sign-in/google/callback?code=x&state=forged")
            .await;
        assert_eq!(res.status_code(), 302);
        let to = location(&res);
        assert!(
            to.starts_with(&format!("{WEB_ORIGIN}/sign-in?error=oauth_state")),
            "{to}"
        );
        // A started consent flow keeps its validated return_to on the failure redirect.
        req.post("/v1/auth/sign-in/google/start")
            .add_query_param("return_to", CONSENT)
            .await;
        let res = req
            .get("/v1/auth/sign-in/google/callback?code=x&state=forged")
            .await;
        let to = location(&res);
        assert!(
            to.starts_with(&format!(
                "{WEB_ORIGIN}/sign-in?error=oauth_state&return_to=%2Foauth%2Fconsent"
            )),
            "{to}"
        );
    })
    .await;
    std::env::remove_var("GOOGLE_CLIENT_ID");
    std::env::remove_var("GOOGLE_CLIENT_SECRET");
}

#[tokio::test]
#[serial]
async fn provider_denial_redirects_to_sign_in_with_oauth_denied() {
    std::env::set_var("GITHUB_CLIENT_ID", "gid");
    std::env::set_var("GITHUB_CLIENT_SECRET", "secret");
    std::env::set_var("GOOGLE_CLIENT_ID", "gid");
    std::env::set_var("GOOGLE_CLIENT_SECRET", "secret");
    serve(|req, _ctx| async move {
        for provider in ["github", "google"] {
            req.post(&format!("/v1/auth/sign-in/{provider}/start"))
                .add_query_param("return_to", CONSENT)
                .await;
            let res = req
                .get(&format!(
                    "/v1/auth/sign-in/{provider}/callback?error=access_denied&state=x"
                ))
                .await;
            assert_eq!(res.status_code(), 302);
            let to = location(&res);
            assert!(
                to.starts_with(&format!(
                    "{WEB_ORIGIN}/sign-in?error=oauth_denied&return_to=%2Foauth%2Fconsent"
                )),
                "{to}"
            );
        }
    })
    .await;
    for k in [
        "GITHUB_CLIENT_ID",
        "GITHUB_CLIENT_SECRET",
        "GOOGLE_CLIENT_ID",
        "GOOGLE_CLIENT_SECRET",
    ] {
        std::env::remove_var(k);
    }
}

/// An attacker starts a consent request in their own browser and mails the victim a sign-in
/// link whose `return_to` points at it: the victim's browser lacks the binding cookie.
#[tokio::test]
#[serial]
async fn magic_link_return_to_cannot_reach_foreign_consent() {
    use super::oauth_authorize::{client, request_id, REDIRECT};
    serve(|mut req, ctx| async move {
        client(&ctx).await;
        let id = request_id(&req, REDIRECT).await;
        req.clear_cookies(); // the victim's browser
        let to = format!("/oauth/consent?request_id={id}");
        let landed = redirect_after(&req, &ctx, &to).await;
        assert_eq!(landed, format!("{WEB_ORIGIN}{to}"));
        let res = req.get(&format!("/v1/oauth/consent/{id}")).await;
        assert_eq!(res.status_code(), 403);
        assert_eq!(res.json::<Value>()["code"], "consent_wrong_browser");
    })
    .await;
}

fn ask(req: &TestServer, email: &str, name: Value) -> axum_test::TestRequest {
    req.post("/v1/auth/magic-link")
        .json(&json!({"email": email, "name": name}))
}

/// Redeems the newest mailed link, then drops the new session cookie so the next anonymous
/// POST is not subject to CSRF.
async fn redeem_last(req: &mut TestServer, mail: &opsagent_brain::mailers::CaptureMailer) {
    assert_eq!(
        redeem(req, &token_of(&last_link(mail))).await.status_code(),
        200
    );
    req.clear_cookies();
}

async fn name_of(ctx: &TestApp, email: &str) -> Option<String> {
    users::Entity::find()
        .filter(users::Column::Email.eq(email))
        .one(&ctx.db)
        .await
        .unwrap()
        .expect("user")
        .name
}

#[tokio::test]
#[serial]
async fn sign_up_name_is_saved_only_after_the_link_or_code_is_redeemed() {
    serve(|mut req, ctx| async move {
        let mail = prepare(&ctx);
        // New address: nothing is saved by the request, not even for a user that gets created.
        assert_eq!(
            ask(&req, "new@example.com", json!("  Ada Lovelace "))
                .await
                .status_code(),
            202
        );
        assert_eq!(name_of(&ctx, "new@example.com").await, None);
        // Redeeming the link proves the email: the name is saved trimmed.
        redeem_last(&mut req, &mail).await;
        assert_eq!(
            name_of(&ctx, "new@example.com").await.as_deref(),
            Some("Ada Lovelace")
        );
        // A later link with another name, or none, never renames the user.
        ask(&req, "new@example.com", json!("Eve")).await;
        redeem_last(&mut req, &mail).await;
        req.post("/v1/auth/magic-link")
            .json(&json!({"email": "new@example.com"}))
            .await;
        redeem_last(&mut req, &mail).await;
        assert_eq!(
            name_of(&ctx, "new@example.com").await.as_deref(),
            Some("Ada Lovelace")
        );
        // An unnamed existing user cannot be named by a request alone; their own sign-in
        // without a name leaves it unset, and a redeemed named link fills it.
        req.post("/v1/auth/magic-link")
            .json(&json!({"email": "old@example.com"}))
            .await;
        redeem_last(&mut req, &mail).await;
        ask(&req, "old@example.com", json!("Mallory")).await;
        assert_eq!(name_of(&ctx, "old@example.com").await, None);
        let spent = last_link(&mail); // Mallory's link, never redeemed
        ask(&req, "old@example.com", json!("Bob")).await;
        redeem_last(&mut req, &mail).await;
        assert_eq!(
            name_of(&ctx, "old@example.com").await.as_deref(),
            Some("Bob")
        );
        assert_eq!(redeem(&req, &token_of(&spent)).await.status_code(), 200);
        assert_eq!(
            name_of(&ctx, "old@example.com").await.as_deref(),
            Some("Bob")
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn sign_up_name_is_saved_when_the_code_is_verified() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        req.post("/v1/auth/magic-link")
            .json(&json!({"email": "code@example.com", "name": "Cy"}))
            .await;
        assert_eq!(name_of(&ctx, "code@example.com").await, None);
        let code = mail.sent().pop().unwrap().subject;
        let code = code.rsplit(' ').next().unwrap();
        let res = req
            .post("/v1/auth/magic-link/verify")
            .add_header("Origin", WEB_ORIGIN)
            .json(&json!({"email": "code@example.com", "code": code}))
            .await;
        assert_eq!(res.status_code(), 200);
        assert_eq!(
            name_of(&ctx, "code@example.com").await.as_deref(),
            Some("Cy")
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn invalid_names_are_ignored_and_the_response_stays_uniform() {
    serve(|mut req, ctx| async move {
        let mail = prepare(&ctx);
        let bad = [
            json!(""),
            json!("   "),
            json!("a".repeat(81)),
            json!("Ada\nLovelace"),
            json!("Ada\u{7}"),
            json!(42),
        ];
        for (i, name) in bad.into_iter().enumerate() {
            let email = format!("bad{i}@example.com");
            let res = req
                .post("/v1/auth/magic-link")
                .json(&json!({"email": email, "name": name}))
                .await;
            // A non-string name is a body error; every string is a uniform 202 and, even once
            // the link is redeemed, no name is stored.
            if name.is_string() || name.is_null() {
                assert_eq!(res.status_code(), 202, "{name}");
                redeem_last(&mut req, &mail).await;
                assert_eq!(name_of(&ctx, &email).await, None, "{name}");
            }
        }
        assert_eq!(mail.sent().len(), 5);
        // 80 characters is allowed.
        req.post("/v1/auth/magic-link")
            .json(&json!({"email": "max@example.com", "name": "é".repeat(80)}))
            .await;
        redeem_last(&mut req, &mail).await;
        assert_eq!(
            name_of(&ctx, "max@example.com")
                .await
                .map(|n| n.chars().count()),
            Some(80)
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn sign_up_for_an_existing_address_answers_and_mails_like_a_new_one() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        let mut seen = Vec::new();
        for email in ["fresh@example.com", "fresh@example.com"] {
            let res = req
                .post("/v1/auth/magic-link")
                .json(&json!({"email": email, "name": "Ann"}))
                .await;
            seen.push((res.status_code(), res.text()));
        }
        assert_eq!(seen[0], seen[1]);
        let sent = mail.sent();
        assert_eq!(sent.len(), 2);
        assert_eq!(
            sent[0].subject.split(':').next(),
            sent[1].subject.split(':').next()
        );
        assert_eq!(users::Entity::find().count(&ctx.db).await.unwrap(), 1);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn a_deleted_accounts_other_session_can_sign_in_again() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        sign_in(&req, &mail, "gone@example.com").await;
        // The account is deleted elsewhere; this browser still holds its session.
        ctx.db
            .execute_unprepared(
                "UPDATE users SET deleted_at = now() WHERE email = 'gone@example.com'",
            )
            .await
            .unwrap();
        let res = req
            .post("/v1/auth/magic-link")
            .json(&json!({ "email": "gone@example.com" }))
            .await;
        assert_ne!(res.status_code(), 403, "{}", res.text());
        assert_eq!(req.get("/v1/auth/me").await.status_code(), 401);
    })
    .await;
}
