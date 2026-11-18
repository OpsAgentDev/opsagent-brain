use axum_test::TestServer;
use chrono::{Duration, Utc};
use opsagent_brain::{models::_entities::audit_events, tokens::hash_token};
use sea_orm::entity::prelude::*;
use serde_json::{json, Value};
use serial_test::serial;

use super::{mcp_auth::call, oauth_authorize::*, support::*};

/// Signs in, creates an org, authorizes and approves: the issued code.
async fn code(req: &TestServer, app: &TestApp) -> String {
    code_for(req, app, REDIRECT).await
}

async fn code_for(req: &TestServer, app: &TestApp, redirect: &str) -> String {
    let mail = prepare(app);
    let csrf = sign_in(req, &mail, "owner@example.com").await;
    let org = create_org(req, &csrf, "Acme").await;
    client(app).await;
    let id = request_id(req, redirect).await;
    let res = decide(req, &csrf, &id, json!({"organisation": slug(&org)})).await;
    assert_eq!(res.status_code(), 200, "{}", res.text());
    query_of(res.json::<Value>()["redirect_to"].as_str().unwrap())["code"].clone()
}

async fn exchange(
    req: &TestServer,
    code: &str,
    verifier: &str,
    redirect: &str,
) -> axum_test::TestResponse {
    req.post("/oauth/token")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", CLIENT),
            ("redirect_uri", redirect),
            ("code_verifier", verifier),
            ("resource", &format!("{BASE}/mcp")),
        ])
        .await
}

async fn refresh(req: &TestServer, token: &str, client_id: &str) -> axum_test::TestResponse {
    req.post("/oauth/token")
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", token),
            ("client_id", client_id),
        ])
        .await
}

/// A code exchanged: the token response body.
async fn tokens(req: &TestServer, app: &TestApp) -> Value {
    let c = code(req, app).await;
    let res = exchange(req, &c, VERIFIER, REDIRECT).await;
    assert_eq!(res.status_code(), 200, "{}", res.text());
    res.json()
}

fn rt(v: &Value) -> String {
    v["refresh_token"].as_str().unwrap().to_owned()
}

fn invalid_grant(res: &axum_test::TestResponse) {
    assert_eq!(res.status_code(), 400, "{}", res.text());
    assert_eq!(res.json::<Value>()["error"], "invalid_grant");
}

async fn grant_revoked(app: &TestApp, access_token: &str) -> bool {
    let (_, g) = app
        .state
        .uow
        .oauth()
        .access_by_hash(&hash_token(access_token))
        .await
        .unwrap()
        .unwrap();
    g.revoked_at.is_some()
}

#[tokio::test]
#[serial]
async fn code_exchange_happy_path() {
    serve(|req, app| async move {
        let c = code(&req, &app).await;
        let res = exchange(&req, &c, VERIFIER, REDIRECT).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        assert_eq!(res.header("cache-control"), "no-store");
        let b: Value = res.json();
        assert_eq!(b["token_type"], "Bearer");
        assert_eq!(b["expires_in"], 3600);
        assert_eq!(b["scope"], "opsagent.read");
        assert!(b["access_token"].as_str().unwrap().len() > 20);
        assert!(!grant_revoked(&app, b["access_token"].as_str().unwrap()).await);
    })
    .await;
}

/// The scope a token carries in practice: whether a write tool runs with it.
async fn can_write(req: &TestServer, access_token: &str) -> bool {
    let args = json!({"id": uuid::Uuid::new_v4().to_string()});
    let got = call(req, access_token, "reopen_finding", args).await;
    // `not_found` means the tool ran; a read-only grant never gets that far.
    match got["result"]["structuredContent"]["code"].as_str() {
        Some("not_found") => true,
        Some("insufficient_scope") => false,
        other => panic!("unexpected {other:?}: {got}"),
    }
}

#[tokio::test]
#[serial]
async fn write_is_granted_only_when_requested_and_approved_and_refresh_keeps_it() {
    serve(|req, app| async move {
        let mail = prepare(&app);
        let csrf = sign_in(&req, &mail, "owner@example.com").await;
        let org = create_org(&req, &csrf, "Acme").await;
        client(&app).await;
        let both = "opsagent.read opsagent.write";
        let res = authorize(&req, &with(params(REDIRECT), "scope", both)).await;
        let id = query_of(res.header("location").to_str().unwrap())["request_id"].clone();
        // Requested but denied: no code, so no grant of any scope.
        let denied = decide(&req, &csrf, &id, json!({"deny": true})).await;
        let to = denied.json::<Value>()["redirect_to"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(query_of(&to)["error"], "access_denied");
        assert!(!query_of(&to).contains_key("code"));
        let grants = app
            .state
            .uow
            .oauth()
            .grants_for_org(org["id"].as_str().unwrap().parse().unwrap());
        assert!(grants.await.unwrap().is_empty());
        // Requested and approved.
        let res = authorize(&req, &with(params(REDIRECT), "scope", both)).await;
        let id = query_of(res.header("location").to_str().unwrap())["request_id"].clone();
        let res = decide(&req, &csrf, &id, json!({"organisation": slug(&org)})).await;
        let c = query_of(res.json::<Value>()["redirect_to"].as_str().unwrap())["code"].clone();
        let first: Value = exchange(&req, &c, VERIFIER, REDIRECT).await.json();
        assert_eq!(first["scope"], both);
        assert!(can_write(&req, first["access_token"].as_str().unwrap()).await);
        let second: Value = refresh(&req, &rt(&first), CLIENT).await.json();
        assert_eq!(second["scope"], both);
        assert!(can_write(&req, second["access_token"].as_str().unwrap()).await);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn refresh_never_widens_a_read_only_grant() {
    serve(|req, app| async move {
        let first = tokens(&req, &app).await;
        assert_eq!(first["scope"], "opsagent.read");
        assert!(!can_write(&req, first["access_token"].as_str().unwrap()).await);
        let res = req
            .post("/oauth/token")
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", rt(&first).as_str()),
                ("client_id", CLIENT),
                ("scope", "opsagent.read opsagent.write"),
            ])
            .await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        let second: Value = res.json();
        assert_eq!(second["scope"], "opsagent.read");
        assert!(!can_write(&req, second["access_token"].as_str().unwrap()).await);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn wrong_verifier_is_invalid_grant() {
    serve(|req, app| async move {
        let c = code(&req, &app).await;
        let wrong = "wrong-verifier-wrong-verifier-wrong-verifier-0123";
        invalid_grant(&exchange(&req, &c, wrong, REDIRECT).await);
        // The failed attempt burned the code.
        invalid_grant(&exchange(&req, &c, VERIFIER, REDIRECT).await);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn code_replay_revokes_issued_grant() {
    serve(|req, app| async move {
        let c = code(&req, &app).await;
        let first: Value = exchange(&req, &c, VERIFIER, REDIRECT).await.json();
        invalid_grant(&exchange(&req, &c, VERIFIER, REDIRECT).await);
        assert!(grant_revoked(&app, first["access_token"].as_str().unwrap()).await);
        invalid_grant(&refresh(&req, &rt(&first), CLIENT).await);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn redirect_uri_mismatch_is_invalid_grant() {
    serve(|req, app| async move {
        let c = code(&req, &app).await;
        invalid_grant(&exchange(&req, &c, VERIFIER, "https://app.example/other").await);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn loopback_port_changed_at_exchange_is_invalid_grant() {
    serve(|req, app| async move {
        let c = code_for(&req, &app, "http://127.0.0.1:60000/callback").await;
        invalid_grant(&exchange(&req, &c, VERIFIER, "http://127.0.0.1:60001/callback").await);
    })
    .await;
}

/// `(actor_id, outcome)` of every `action` audit row.
async fn audits(app: &TestApp, action: &str) -> Vec<(Option<String>, Option<String>)> {
    audit_events::Entity::find()
        .filter(audit_events::Column::Action.eq(action))
        .all(&app.db)
        .await
        .unwrap()
        .into_iter()
        .map(|r| (r.actor_id, r.outcome))
        .collect()
}

async fn user_id(app: &TestApp, access_token: &str) -> String {
    let (_, g) = app
        .state
        .uow
        .oauth()
        .access_by_hash(&hash_token(access_token))
        .await
        .unwrap()
        .unwrap();
    let members = app
        .state
        .uow
        .orgs()
        .members(g.organisation_id)
        .await
        .unwrap();
    members
        .iter()
        .find(|m| m.id == g.member_id)
        .unwrap()
        .user_id
        .to_string()
}

#[tokio::test]
#[serial]
async fn token_issued_and_replay_audit_name_the_user() {
    serve(|req, app| async move {
        let c = code(&req, &app).await;
        let first: Value = exchange(&req, &c, VERIFIER, REDIRECT).await.json();
        let user = user_id(&app, first["access_token"].as_str().unwrap()).await;
        assert_eq!(
            audits(&app, "oauth.token.issued").await,
            [(Some(user.clone()), Some("success".into()))]
        );
        invalid_grant(&exchange(&req, &c, VERIFIER, REDIRECT).await);
        assert_eq!(
            audits(&app, "oauth.grant.revoked").await,
            [(Some(user), Some("code_replay".into()))]
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn removed_member_refresh_is_invalid_grant_and_revokes() {
    serve(|req, app| async move {
        let t = tokens(&req, &app).await;
        let (_, g) = app
            .state
            .uow
            .oauth()
            .access_by_hash(&hash_token(t["access_token"].as_str().unwrap()))
            .await
            .unwrap()
            .unwrap();
        assert!(app
            .state
            .uow
            .orgs()
            .remove_member(g.organisation_id, g.member_id)
            .await
            .unwrap());
        invalid_grant(&refresh(&req, &rt(&t), CLIENT).await);
        assert!(grant_revoked(&app, t["access_token"].as_str().unwrap()).await);
        let rows = audits(&app, "oauth.grant.revoked").await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1.as_deref(), Some("member_gone"));
    })
    .await;
}

#[tokio::test]
#[serial]
async fn refresh_rotates() {
    serve(|req, app| async move {
        let t = tokens(&req, &app).await;
        let res = refresh(&req, &rt(&t), CLIENT).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        assert_eq!(res.header("cache-control"), "no-store");
        let next: Value = res.json();
        assert_ne!(rt(&next), rt(&t));
        assert_ne!(next["access_token"], t["access_token"]);
        assert_eq!(refresh(&req, &rt(&next), CLIENT).await.status_code(), 200);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn refresh_reuse_within_grace_gets_second_successor() {
    serve(|req, app| async move {
        let t = tokens(&req, &app).await;
        let a: Value = refresh(&req, &rt(&t), CLIENT).await.json();
        let res = refresh(&req, &rt(&t), CLIENT).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        let b: Value = res.json();
        assert_ne!(rt(&a), rt(&b));
        assert_eq!(refresh(&req, &rt(&a), CLIENT).await.status_code(), 200);
        assert_eq!(refresh(&req, &rt(&b), CLIENT).await.status_code(), 200);
        assert!(!grant_revoked(&app, t["access_token"].as_str().unwrap()).await);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn third_presentation_inside_grace_revokes() {
    serve(|req, app| async move {
        let t = tokens(&req, &app).await;
        let a: Value = refresh(&req, &rt(&t), CLIENT).await.json();
        assert_eq!(refresh(&req, &rt(&t), CLIENT).await.status_code(), 200);
        invalid_grant(&refresh(&req, &rt(&t), CLIENT).await);
        assert!(grant_revoked(&app, t["access_token"].as_str().unwrap()).await);
        invalid_grant(&refresh(&req, &rt(&a), CLIENT).await);
        let user = user_id(&app, t["access_token"].as_str().unwrap()).await;
        assert_eq!(
            audits(&app, "oauth.grant.revoked").await,
            [(Some(user), Some("refresh_reuse".into()))]
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn refresh_reuse_after_31s_revokes_grant() {
    serve(|req, app| async move {
        let t = tokens(&req, &app).await;
        let next: Value = refresh(&req, &rt(&t), CLIENT).await.json();
        let later = Utc::now() + Duration::seconds(31);
        let refresh_grant = &app.state.actions.oauth.refresh_grant;
        let e = refresh_grant.run(&rt(&t), CLIENT, later).await.unwrap_err();
        assert_eq!(e.error, "invalid_grant");
        assert!(grant_revoked(&app, t["access_token"].as_str().unwrap()).await);
        invalid_grant(&refresh(&req, &rt(&next), CLIENT).await);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn refresh_by_other_client_is_invalid_grant() {
    serve(|req, app| async move {
        let t = tokens(&req, &app).await;
        invalid_grant(&refresh(&req, &rt(&t), "someone-else").await);
        // The refusal neither spent the token nor revoked the grant.
        assert_eq!(refresh(&req, &rt(&t), CLIENT).await.status_code(), 200);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn revoke_unknown_token_is_200() {
    serve(|req, app| async move {
        let res = req.post("/oauth/revoke").form(&[("token", "nope")]).await;
        assert_eq!(res.status_code(), 200);
        let t = tokens(&req, &app).await;
        let res = req
            .post("/oauth/revoke")
            .form(&[("token", rt(&t).as_str())])
            .await;
        assert_eq!(res.status_code(), 200);
        assert!(grant_revoked(&app, t["access_token"].as_str().unwrap()).await);
        invalid_grant(&refresh(&req, &rt(&t), CLIENT).await);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn errors_are_rfc6749_json() {
    serve(|req, _| async move {
        for (res, error) in [
            (
                req.post("/oauth/token")
                    .form(&[("grant_type", "password")])
                    .await,
                "unsupported_grant_type",
            ),
            (
                req.post("/oauth/token")
                    .form(&[("grant_type", "refresh_token")])
                    .await,
                "invalid_request",
            ),
            (
                req.post("/oauth/token").json(&json!({})).await,
                "invalid_request",
            ),
        ] {
            assert_eq!(res.status_code(), 400);
            assert_eq!(res.header("content-type"), "application/json");
            let b: Value = res.json();
            assert_eq!(b["error"], error);
            assert!(b["error_description"].is_string());
        }
    })
    .await;
}

#[tokio::test]
#[serial]
async fn token_and_revoke_share_a_per_ip_limit() {
    serve(|req, _| async move {
        let token = || {
            req.post("/oauth/token")
                .add_header("x-forwarded-for", "198.51.100.9")
                .form(&[("grant_type", "password")])
        };
        for _ in 0..299 {
            assert_eq!(token().await.status_code(), 400);
        }
        let revoke = req
            .post("/oauth/revoke")
            .add_header("x-forwarded-for", "198.51.100.9")
            .form(&[("token", "nope")])
            .await;
        assert_eq!(revoke.status_code(), 200);
        let res = token().await;
        assert_eq!(res.status_code(), 429);
        assert_eq!(res.json::<Value>()["error"], "slow_down");
        let other = req
            .post("/oauth/token")
            .add_header("x-forwarded-for", "198.51.100.10")
            .form(&[("grant_type", "password")])
            .await;
        assert_eq!(other.status_code(), 400);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn client_revoke_is_audited_once_as_the_client() {
    serve(|req, app| async move {
        let t = tokens(&req, &app).await;
        let (_, g) = app
            .state
            .uow
            .oauth()
            .access_by_hash(&hash_token(t["access_token"].as_str().unwrap()))
            .await
            .unwrap()
            .unwrap();
        for _ in 0..2 {
            let res = req
                .post("/oauth/revoke")
                .form(&[("token", rt(&t).as_str())])
                .await;
            assert_eq!(res.status_code(), 200);
        }
        assert_eq!(
            audits(&app, "oauth.grant.revoked").await,
            [(Some(g.id.to_string()), Some("client_revoked".into()))]
        );
    })
    .await;
}
