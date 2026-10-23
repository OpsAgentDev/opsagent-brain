//! Slack install, channels, recipients, unsubscribe (Plan 2 Task 9).
use std::sync::Arc;

use axum_test::TestServer;
use loco_rs::{app::AppContext, prelude::*};
use opsagent_brain::{
    actions::uow::Repos,
    actions::{
        integrations::open_token,
        recipients::tokens::{self as recipient_service, email_hash},
    },
    adapters::{
        db::Pg,
        slack::{HttpSlack, SlackClient},
    },
    app::{self, actions, kek},
    mailers::CaptureMailer,
    models::_entities::{
        audit_events, email_suppressions, integrations, organisations, recipients, users,
    },
};
use opsagent_core::org::{OrganisationsRepo, Role};
use serde_json::{json, Value};
use serial_test::serial;
use wiremock::{
    matchers::{body_string_contains, method, path},
    Mock, MockServer, ResponseTemplate,
};

use super::support::*;

/// Points the app at `slack` and configures Slack client credentials.
fn use_slack(ctx: &AppContext, slack: &MockServer) {
    let c: Arc<dyn SlackClient> = Arc::new(HttpSlack::new(slack.uri()).unwrap());
    // Actions hold the adapters they were built with.
    opsagent_brain::app::replace_deps(ctx, |d| {
        d.config.slack_client_id = "cid".into();
        d.config.slack_client_secret = "csecret".into();
        d.slack = c;
    })
    .unwrap();
}

async fn start(req: &TestServer, csrf: &str, org: &str) -> axum_test::TestResponse {
    req.post(&format!("/v1/orgs/{org}/integrations/slack/start"))
        .add_header("X-CSRF-Token", csrf)
        .await
}

/// The `state` query value of a start response's authorize URL.
fn state_of(res: &axum_test::TestResponse) -> String {
    let url = res.json::<Value>()["authorize_url"]
        .as_str()
        .unwrap()
        .to_string();
    let u = reqwest::Url::parse(&url).unwrap();
    u.query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned()
}

async fn callback(req: &TestServer, code: &str, state: &str) -> axum_test::TestResponse {
    req.get(&format!(
        "/v1/integrations/slack/callback?code={code}&state={state}"
    ))
    .await
}

async fn mock_oauth(slack: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/oauth.v2.access"))
        .and(body_string_contains("code=good"))
        .and(body_string_contains("client_secret=csecret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true, "access_token": "xoxb-secret-token", "token_type": "bot",
            "scope": "chat:write,channels:read", "bot_user_id": "U0BOT",
            "team": {"id": "T1", "name": "Acme"}
        })))
        .mount(slack)
        .await;
}

/// Owner signs in, creates an org and completes a Slack install. Returns `(csrf, org slug)`.
async fn installed(
    req: &TestServer,
    ctx: &AppContext,
    mail: &CaptureMailer,
    slack: &MockServer,
) -> (String, String) {
    use_slack(ctx, slack);
    mock_oauth(slack).await;
    let t = sign_in(req, mail, "owner@example.com").await;
    let org = slug(&create_org(req, &t, "Acme").await);
    let state = state_of(&start(req, &t, &org).await);
    assert_eq!(callback(req, "good", &state).await.status_code(), 302);
    (t, org)
}

fn guard(ctx: &AppContext) -> Arc<opsagent_brain::actions::recipients::MailGuard> {
    actions(ctx).unwrap().recipients.mail_guard.clone()
}

async fn audits(ctx: &AppContext, action: &str) -> u64 {
    audit_events::Entity::find()
        .filter(audit_events::Column::Action.eq(action))
        .count(&ctx.db)
        .await
        .unwrap()
}

/// Signs `email` in as a `member` of org `slug` (the current owner session is replaced).
async fn as_member(
    req: &mut TestServer,
    ctx: &AppContext,
    mail: &CaptureMailer,
    org: &str,
    email: &str,
) -> String {
    req.clear_cookies();
    let t = sign_in(req, mail, email).await;
    let user = users::Entity::find()
        .filter(users::Column::Email.eq(email))
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap();
    let o = organisations::Entity::find()
        .filter(organisations::Column::Slug.eq(org))
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap();
    Pg::new(&ctx.db)
        .add_member(o.id, user.id, Role::Member)
        .await
        .unwrap();
    t
}

#[tokio::test]
#[serial]
async fn start_returns_authorize_url_and_needs_config_and_owner() {
    serve(|mut req, ctx| async move {
        let mail = prepare(&ctx);
        let t = sign_in(&req, &mail, "owner@example.com").await;
        let org = slug(&create_org(&req, &t, "Acme").await);
        let res = start(&req, &t, &org).await;
        assert_eq!(res.status_code(), 503);
        assert_eq!(res.json::<Value>()["code"], "slack_not_configured");

        let slack = MockServer::start().await;
        use_slack(&ctx, &slack);
        let res = start(&req, &t, &org).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        let url = res.json::<Value>()["authorize_url"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(
            url.starts_with("https://slack.com/oauth/v2/authorize?"),
            "{url}"
        );
        let u = reqwest::Url::parse(&url).unwrap();
        let q: std::collections::HashMap<_, _> = u.query_pairs().into_owned().collect();
        assert_eq!(q["client_id"], "cid");
        assert_eq!(
            q["scope"],
            "chat:write,chat:write.public,channels:read,groups:read"
        );
        assert_eq!(
            q["redirect_uri"],
            "http://localhost:5150/v1/integrations/slack/callback"
        );
        assert!(q["state"].len() >= 43);

        let tm = as_member(&mut req, &ctx, &mail, &org, "member@example.com").await;
        let res = start(&req, &tm, &org).await;
        assert_eq!(res.status_code(), 403);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn callback_without_session_redirects_signed_out() {
    serve(|req, _ctx| async move {
        let res = callback(&req, "good", "x").await;
        assert_eq!(res.status_code(), 302);
        assert_eq!(
            res.header("location"),
            "http://localhost:3000/settings/delivery?slack=error&code=signed_out"
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn forged_or_superseded_state_is_403() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        let slack = MockServer::start().await;
        use_slack(&ctx, &slack);
        mock_oauth(&slack).await;
        let t = sign_in(&req, &mail, "owner@example.com").await;
        let org = slug(&create_org(&req, &t, "Acme").await);
        let first = state_of(&start(&req, &t, &org).await);
        let res = callback(&req, "good", "forged").await;
        assert_eq!(res.status_code(), 403);
        assert_eq!(res.json::<Value>()["code"], "oauth_state");

        // A second start replaces the first state.
        let first_again = state_of(&start(&req, &t, &org).await);
        let second = state_of(&start(&req, &t, &org).await);
        assert_ne!(first, second);
        assert_eq!(
            callback(&req, "good", &first_again).await.status_code(),
            403
        );
        // The failed attempt consumed the stored state, so even the latest one is now spent.
        assert_eq!(callback(&req, "good", &second).await.status_code(), 403);
        assert_eq!(
            integrations::Entity::find().count(&ctx.db).await.unwrap(),
            0
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn callback_seals_token_and_redirects_and_state_is_single_use() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        let slack = MockServer::start().await;
        use_slack(&ctx, &slack);
        mock_oauth(&slack).await;
        let t = sign_in(&req, &mail, "owner@example.com").await;
        let org = slug(&create_org(&req, &t, "Acme").await);
        let state = state_of(&start(&req, &t, &org).await);
        let res = callback(&req, "good", &state).await;
        assert_eq!(res.status_code(), 302);
        assert_eq!(
            res.header("location"),
            "http://localhost:3000/settings/delivery?slack=connected"
        );
        assert_eq!(callback(&req, "good", &state).await.status_code(), 403);

        let row = integrations::Entity::find()
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.kind, "slack");
        assert_eq!(row.status, "active");
        assert_eq!(row.config["team_id"], "T1");
        assert_eq!(row.config["team_name"], "Acme");
        assert_eq!(row.config["bot_user_id"], "U0BOT");
        assert_ne!(row.ciphertext, b"xoxb-secret-token".to_vec());
        let sealed = Pg::new(&ctx.db)
            .integrations()
            .list(row.organisation_id)
            .await
            .unwrap();
        let plain = open_token(&Pg::new(&ctx.db), kek(&ctx).unwrap().as_ref(), &sealed[0])
            .await
            .unwrap();
        assert_eq!(plain.as_str(), "xoxb-secret-token");
        assert_eq!(audits(&ctx, "integration.slack_connect").await, 1);
        let audit = audit_events::Entity::find().all(&ctx.db).await.unwrap();
        assert!(!serde_json::to_string(&audit).unwrap().contains("xoxb"));

        // A Slack error code comes back as a redirect, never provider text.
        let state = state_of(&start(&req, &t, &org).await);
        let res = callback(&req, "bad", &state).await;
        assert_eq!(res.status_code(), 302);
        let loc = res.header("location");
        assert!(
            loc.to_str()
                .unwrap()
                .ends_with("?slack=error&code=http_404"),
            "{loc:?}"
        );

        let list = req
            .get(&format!("/v1/orgs/{org}/integrations"))
            .await
            .json::<Value>();
        assert_eq!(list[0]["team_name"], "Acme");
        let id = list[0]["id"].as_str().unwrap();
        Mock::given(method("POST"))
            .and(path("/auth.revoke"))
            .and(wiremock::matchers::header(
                "authorization",
                "Bearer xoxb-secret-token",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"ok": true, "revoked": true})),
            )
            .expect(1)
            .mount(&slack)
            .await;
        let res = req
            .delete(&format!("/v1/orgs/{org}/integrations/{id}"))
            .add_header("X-CSRF-Token", &t)
            .await;
        assert_eq!(res.status_code(), 204);
        assert_eq!(
            integrations::Entity::find().count(&ctx.db).await.unwrap(),
            0
        );
        assert_eq!(audits(&ctx, "integration.delete").await, 1);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn channels_map_conversations_list_and_revoked_is_503() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        let slack = MockServer::start().await;
        let (_t, org) = installed(&req, &ctx, &mail, &slack).await;
        Mock::given(method("GET"))
            .and(path("/conversations.list"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ok": true,
                "channels": [{"id": "C1", "name": "ops", "is_private": false},
                             {"id": "G2", "name": "secret", "is_private": true}],
                "response_metadata": {"next_cursor": ""}
            })))
            .up_to_n_times(1)
            .mount(&slack)
            .await;
        let url = format!("/v1/orgs/{org}/integrations/slack/channels");
        let res = req.get(&url).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        assert_eq!(
            res.json::<Value>(),
            json!([{"id": "C1", "name": "ops"}, {"id": "G2", "name": "secret"}])
        );

        // Slack reports the token revoked: the integration is marked and the API says 503.
        Mock::given(method("GET"))
            .and(path("/conversations.list"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"ok": false, "error": "token_revoked"})),
            )
            .mount(&slack)
            .await;
        let res = req.get(&url).await;
        assert_eq!(res.status_code(), 503);
        assert_eq!(res.json::<Value>()["code"], "slack_revoked");
        let row = integrations::Entity::find()
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.status, "revoked");
        // Once revoked, Slack is not called again.
        let calls = slack.received_requests().await.unwrap().len();
        assert_eq!(req.get(&url).await.status_code(), 503);
        assert_eq!(slack.received_requests().await.unwrap().len(), calls);
    })
    .await;
}

async fn add_recipient(
    req: &TestServer,
    t: &str,
    org: &str,
    body: Value,
) -> axum_test::TestResponse {
    req.post(&format!("/v1/orgs/{org}/recipients"))
        .add_header("X-CSRF-Token", t)
        .json(&body)
        .await
}

#[tokio::test]
#[serial]
async fn email_recipient_confirms_by_link_and_member_is_active() {
    serve(|mut req, ctx| async move {
        let mail = prepare(&ctx);
        let t = sign_in(&req, &mail, "owner@example.com").await;
        let org = slug(&create_org(&req, &t, "Acme").await);
        let res = add_recipient(&req, &t, &org, json!({"email": "Ext@Example.com"})).await;
        assert_eq!(res.status_code(), 201, "{}", res.text());
        let r = res.json::<Value>();
        assert_eq!(
            (r["status"].as_str(), r["email"].as_str()),
            (Some("pending"), Some("ext@example.com"))
        );
        let dup = add_recipient(&req, &t, &org, json!({"email": "ext@example.com"})).await;
        assert_eq!(dup.status_code(), 409);
        let both = add_recipient(
            &req,
            &t,
            &org,
            json!({"email": "a@example.com", "member_id": r["id"]}),
        )
        .await;
        assert_eq!(both.status_code(), 422);

        let link = last_link(&mail);
        assert!(
            link.starts_with("http://localhost:3000/recipients/confirm?token="),
            "{link}"
        );
        let token = token_of(&link);
        let row = recipients::Entity::find()
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(row.confirm_token_hash.as_deref(), Some(token.as_str()));
        let confirm = |tok: String| {
            let req = &req;
            async move {
                req.post("/v1/recipients/confirm")
                    .json(&json!({"token": tok}))
                    .await
            }
        };
        assert_eq!(confirm("nope".into()).await.status_code(), 410);
        assert_eq!(confirm(token.clone()).await.status_code(), 204);
        assert_eq!(confirm(token).await.status_code(), 410);
        let row = recipients::Entity::find()
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.status, "active");

        // A member recipient skips confirmation; members may list but not add or delete.
        let owner_member = req
            .get(&format!("/v1/orgs/{org}/members"))
            .await
            .json::<Value>()[0]["id"]
            .clone();
        let sent = mail.sent().len();
        let res = add_recipient(&req, &t, &org, json!({"member_id": owner_member})).await;
        assert_eq!(res.status_code(), 201, "{}", res.text());
        assert_eq!(res.json::<Value>()["status"], "active");
        assert_eq!(mail.sent().len(), sent);
        assert_eq!(audits(&ctx, "recipient.create").await, 2);

        let tm = as_member(&mut req, &ctx, &mail, &org, "member@example.com").await;
        let page = req
            .get(&format!("/v1/orgs/{org}/recipients"))
            .await
            .json::<Value>();
        assert_eq!(page["items"].as_array().unwrap().len(), 2);
        assert_eq!(
            add_recipient(&req, &tm, &org, json!({"email": "x@example.com"}))
                .await
                .status_code(),
            403
        );
        let res = req
            .delete(&format!("/v1/orgs/{org}/recipients/{}", row.id))
            .add_header("X-CSRF-Token", &tm)
            .await;
        assert_eq!(res.status_code(), 403);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn unsubscribe_link_is_stable_and_suppresses_the_address() {
    serve(|mut req, ctx| async move {
        let mail = prepare(&ctx);
        let (t, org, conn) =
            fake_connection(&req, &mail, "owner@example.com", "Acme", "clean").await;
        let res = add_recipient(
            &req,
            &t,
            &org,
            json!({"email": "ext@example.com", "connection_id": conn}),
        )
        .await;
        assert_eq!(res.status_code(), 201, "{}", res.text());
        assert_eq!(res.json::<Value>()["connection_id"], conn);
        // Same email org-wide is a separate route.
        assert_eq!(
            add_recipient(&req, &t, &org, json!({"email": "ext@example.com"}))
                .await
                .status_code(),
            201
        );
        let row = recipients::Entity::find()
            .filter(recipients::Column::ConnectionId.is_not_null())
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        let secret = app::state(&ctx)
            .unwrap()
            .config
            .unsubscribe_key()
            .to_owned();
        // Two mails carry the same link, and both work (idempotent).
        let web = "http://localhost:3000";
        let first = recipient_service::unsubscribe_url(web, &secret, row.id);
        let second = recipient_service::unsubscribe_url(web, &secret, row.id);
        assert_eq!(first, second);
        let token = first.rsplit('/').next().unwrap().to_string();
        assert_eq!(
            req.post(&format!("/v1/unsubscribe/{token}"))
                .await
                .status_code(),
            204
        );
        assert_eq!(
            req.post(&format!("/v1/unsubscribe/{token}"))
                .await
                .status_code(),
            204
        );
        let forged = format!("{}.AAAA", row.id.simple());
        assert_eq!(
            req.post(&format!("/v1/unsubscribe/{forged}"))
                .await
                .status_code(),
            410
        );
        let other = recipient_service::unsubscribe_token("another-secret-entirely", row.id);
        assert_eq!(
            req.post(&format!("/v1/unsubscribe/{other}"))
                .await
                .status_code(),
            410
        );
        let row = recipients::Entity::find_by_id(row.id)
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        assert!(row.unsubscribed_at.is_some());
        assert_eq!(audits(&ctx, "recipient.unsubscribe").await, 1);
        let s = suppression(email_hash("EXT@example.com"))
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(s.reason, "unsubscribed");

        // Another organisation adding the address gets a 201 but no mail is sent.
        req.clear_cookies();
        let t2 = sign_in(&req, &mail, "other@example.com").await;
        let org2 = slug(&create_org(&req, &t2, "Other").await);
        let sent = mail.sent().len();
        assert_eq!(
            add_recipient(&req, &t2, &org2, json!({"email": "ext@example.com"}))
                .await
                .status_code(),
            201
        );
        assert_eq!(mail.sent().len(), sent);

        // The owner deletes; the token then stops working.
        req.clear_cookies();
        let t = sign_in(&req, &mail, "owner@example.com").await;
        let url = format!("/v1/orgs/{org}/recipients/{}", row.id);
        assert_eq!(
            req.delete(&url)
                .add_header("X-CSRF-Token", &t)
                .await
                .status_code(),
            204
        );
        assert_eq!(
            req.delete(&url)
                .add_header("X-CSRF-Token", &t)
                .await
                .status_code(),
            404
        );
        assert_eq!(audits(&ctx, "recipient.delete").await, 1);
        assert_eq!(
            req.post(&format!("/v1/unsubscribe/{token}"))
                .await
                .status_code(),
            410
        );
    })
    .await;
}

/// The suppression row for an email hash (any organisation).
fn suppression(hash: String) -> sea_orm::Select<email_suppressions::Entity> {
    email_suppressions::Entity::find().filter(email_suppressions::Column::EmailHash.eq(hash))
}

/// Confirm mails sent to `email` so far.
fn mails_to(mail: &CaptureMailer, email: &str) -> usize {
    mail.sent().iter().filter(|m| m.to == email).count()
}

#[tokio::test]
#[serial]
async fn confirm_mails_are_capped_and_ignored_addresses_suppressed() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        let (t, org, c1) = fake_connection(&req, &mail, "owner@example.com", "Acme", "clean").await;
        let conn = |name: &'static str| {
            let (req, t, org) = (&req, &t, &org);
            async move { create_connection(req, t, org, "fake", name).await["id"].clone() }
        };
        let (c2, c3) = (conn("clean").await, conn("clean").await);
        // Ignored: two unconfirmed mails, then the address is suppressed and gets no third.
        for c in [Value::Null, json!(c1)] {
            add_recipient(
                &req,
                &t,
                &org,
                json!({"email": "quiet@example.com", "connection_id": c}),
            )
            .await;
        }
        assert_eq!(mails_to(&mail, "quiet@example.com"), 2);
        let res = add_recipient(
            &req,
            &t,
            &org,
            json!({"email": "quiet@example.com", "connection_id": c2}),
        )
        .await;
        assert_eq!(res.status_code(), 201);
        assert_eq!(mails_to(&mail, "quiet@example.com"), 2);
        let s = suppression(email_hash("quiet@example.com"))
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(s.reason, "ignored");

        // One owner, each mail confirmed: the per-owner count resets, so only the
        // per-(org, address) 3/day cap withholds the 4th.
        for c in [Value::Null, json!(c1), json!(c2), json!(c3)] {
            add_recipient(
                &req,
                &t,
                &org,
                json!({"email": "busy@example.com", "connection_id": c}),
            )
            .await;
            if let Some(m) = mail
                .sent()
                .into_iter()
                .rev()
                .find(|m| m.to == "busy@example.com")
            {
                let tok = token_of(
                    m.text
                        .split_whitespace()
                        .find(|w| w.starts_with("http"))
                        .unwrap(),
                );
                req.post("/v1/recipients/confirm")
                    .json(&json!({"token": tok}))
                    .await;
            }
        }
        assert_eq!(mails_to(&mail, "busy@example.com"), 3);
        assert!(suppression(email_hash("busy@example.com"))
            .one(&ctx.db)
            .await
            .unwrap()
            .is_none());

        // Per organisation: 20 a day. Six attempts above passed the address cap (5 sent, 1 refused
        // as ignored), so 14 remain.
        for i in 0..20 {
            let res = add_recipient(
                &req,
                &t,
                &org,
                json!({"email": format!("r{i}@example.com")}),
            )
            .await;
            assert_eq!(res.status_code(), 201);
        }
        let to_r = mail.sent().iter().filter(|m| m.to.starts_with('r')).count();
        assert_eq!(to_r, 14);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn unconfirmed_confirm_mails_per_owner_cap_at_two_across_orgs() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        let (t, org, c1) = fake_connection(&req, &mail, "owner@example.com", "Acme", "clean").await;
        let org2 = slug(&create_org(&req, &t, "Second").await);
        for (o, c) in [(&org, Value::Null), (&org, json!(c1)), (&org2, Value::Null)] {
            add_recipient(
                &req,
                &t,
                o,
                json!({"email": "far@example.com", "connection_id": c}),
            )
            .await;
        }
        assert_eq!(mails_to(&mail, "far@example.com"), 2);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn org_names_refuse_control_chars_and_mail_caps_the_name() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        let t = sign_in(&req, &mail, "owner@example.com").await;
        for bad in [
            "Evil\nBcc: victim@example.com",
            "Evil\r\nX",
            "Abc\u{202E}fdp.exe",
        ] {
            let res = req
                .post("/v1/orgs")
                .add_header("X-CSRF-Token", &t)
                .json(&json!({ "name": bad }))
                .await;
            assert_eq!(res.status_code(), 422, "{bad:?}");
        }
        let org = slug(&create_org(&req, &t, &format!("Long {}", "x".repeat(90))).await);
        add_recipient(&req, &t, &org, json!({"email": "ext@example.com"})).await;
        let m = mail.sent().pop().unwrap();
        assert!(m.subject.chars().count() <= "Confirm OpsAgent reports for ".len() + 60);
        assert!(!m.text.contains(&"x".repeat(60)));
        let res = req
            .post(&format!("/v1/orgs/{org}/invites"))
            .add_header("X-CSRF-Token", &t)
            .json(&json!({"email": "inv@example.com", "role": "member"}))
            .await;
        assert_eq!(res.status_code(), 201, "{}", res.text());
        let m = mail.sent().pop().unwrap();
        assert!(!m.subject.contains(&"x".repeat(60)), "{}", m.subject);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn ignored_suppression_is_per_org_and_expires() {
    serve(|mut req, ctx| async move {
        let mail = prepare(&ctx);
        let (t, org, c1) = fake_connection(&req, &mail, "owner@example.com", "Acme", "clean").await;
        let c2 = create_connection(&req, &t, &org, "fake", "clean").await["id"].clone();
        for c in [Value::Null, json!(c1), c2] {
            add_recipient(
                &req,
                &t,
                &org,
                json!({"email": "quiet@example.com", "connection_id": c}),
            )
            .await;
        }
        assert_eq!(mails_to(&mail, "quiet@example.com"), 2);

        // Org B still reaches the address.
        req.clear_cookies();
        let tb = sign_in(&req, &mail, "b@example.com").await;
        let org_b = slug(&create_org(&req, &tb, "Other").await);
        add_recipient(&req, &tb, &org_b, json!({"email": "quiet@example.com"})).await;
        assert_eq!(mails_to(&mail, "quiet@example.com"), 3);

        // 90 days later (and the 30-day counter long gone), org A may mail again.
        let row = email_suppressions::Entity::find()
            .filter(email_suppressions::Column::Reason.eq("ignored"))
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        let left = row.expires_at.unwrap() - chrono::Utc::now().fixed_offset();
        assert!(left.num_days() >= 89 && left.num_days() <= 90, "{left}");
        let mut a: email_suppressions::ActiveModel = row.into();
        a.expires_at = Set(Some(
            (chrono::Utc::now() - chrono::Duration::seconds(1)).into(),
        ));
        a.update(&ctx.db).await.unwrap();
        let mut c = redis_of(&ctx).get_connection().unwrap();
        let keys: Vec<String> = opsagent_ledger::redis::cmd("KEYS")
            .arg("*recipient_confirm:*")
            .query(&mut c)
            .unwrap();
        let _: () = opsagent_ledger::redis::cmd("DEL")
            .arg(&keys)
            .query(&mut c)
            .unwrap();
        req.clear_cookies();
        let t = sign_in(&req, &mail, "owner@example.com").await;
        let c3 = create_connection(&req, &t, &org, "fake", "clean").await["id"].clone();
        add_recipient(
            &req,
            &t,
            &org,
            json!({"email": "quiet@example.com", "connection_id": c3}),
        )
        .await;
        assert_eq!(mails_to(&mail, "quiet@example.com"), 4);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn a_slack_workspace_links_to_one_org() {
    serve(|mut req, ctx| async move {
        let mail = prepare(&ctx);
        let slack = MockServer::start().await;
        installed(&req, &ctx, &mail, &slack).await;
        req.clear_cookies();
        let t = sign_in(&req, &mail, "b@example.com").await;
        let org_b = slug(&create_org(&req, &t, "Other").await);
        let state = state_of(&start(&req, &t, &org_b).await);
        let res = callback(&req, "good", &state).await;
        assert_eq!(res.status_code(), 302);
        assert_eq!(
            res.header("location"),
            "http://localhost:3000/settings/delivery?slack=error&code=slack_workspace_in_use"
        );
        assert_eq!(
            integrations::Entity::find().count(&ctx.db).await.unwrap(),
            1
        );
        // The holding org can still reinstall.
        req.clear_cookies();
        let t = sign_in(&req, &mail, "owner@example.com").await;
        let org_a = organisations::Entity::find()
            .filter(organisations::Column::Name.eq("Acme"))
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap()
            .slug;
        let state = state_of(&start(&req, &t, &org_a).await);
        let res = callback(&req, "good", &state).await;
        assert_eq!(
            res.header("location"),
            "http://localhost:3000/settings/delivery?slack=connected"
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn connection_patch_sets_and_clears_slack_channel() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        let (t, org, id) = fake_connection(&req, &mail, "o@example.com", "Org", "clean").await;
        let url = format!("/v1/orgs/{org}/connections/{id}");
        let patch = |v: &str| {
            let (req, url, t, v) = (&req, &url, &t, v.to_string());
            async move {
                req.patch(url)
                    .add_header("X-CSRF-Token", t)
                    .json(&json!({"slack_channel_id": v}))
                    .await
            }
        };
        assert_eq!(patch("general").await.status_code(), 422);
        let res = patch("C0123ABCD").await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        assert_eq!(res.json::<Value>()["slack_channel_id"], "C0123ABCD");
        assert_eq!(
            patch("").await.json::<Value>()["slack_channel_id"],
            Value::Null
        );
    })
    .await;
}

/// Owner `email` signs in (fresh session), creates an org with an extra connection; returns
/// `(csrf, slug, [org-wide, connection 1, connection 2])` recipient routes.
async fn org_with_routes(
    req: &mut TestServer,
    mail: &CaptureMailer,
    email: &str,
) -> (String, String, [Value; 3]) {
    req.clear_cookies();
    let (t, org, c1) = fake_connection(req, mail, email, email, "clean").await;
    let c2 = create_connection(req, &t, &org, "fake", "clean").await["id"].clone();
    (t, org, [Value::Null, json!(c1), c2])
}

/// Adds `email` on `route`, then confirms it if a confirm mail went out.
async fn add_and_confirm(
    req: &TestServer,
    mail: &CaptureMailer,
    t: &str,
    org: &str,
    email: &str,
    route: &Value,
) {
    let before = mails_to(mail, email);
    add_recipient(req, t, org, json!({"email": email, "connection_id": route})).await;
    if mails_to(mail, email) > before {
        let m = mail
            .sent()
            .into_iter()
            .rev()
            .find(|m| m.to == email)
            .unwrap();
        let tok = token_of(
            m.text
                .split_whitespace()
                .find(|w| w.starts_with("http"))
                .unwrap(),
        );
        let res = req
            .post("/v1/recipients/confirm")
            .json(&json!({"token": tok}))
            .await;
        assert_eq!(res.status_code(), 204);
    }
}

async fn blocked(ctx: &AppContext) -> Option<email_suppressions::Model> {
    email_suppressions::Entity::find()
        .filter(email_suppressions::Column::Reason.eq("confirm_blocked"))
        .one(&ctx.db)
        .await
        .unwrap()
}

#[tokio::test]
#[serial]
async fn five_distinct_owners_block_confirms_but_not_confirmed_deliveries() {
    serve(|mut req, ctx| async move {
        let mail = prepare(&ctx);
        // A recipient that confirmed before the block.
        let (t, org_z, _) = org_with_routes(&mut req, &mail, "z@example.com").await;
        add_and_confirm(&req, &mail, &t, &org_z, "target@example.com", &Value::Null).await;
        let owners = [
            "a@example.com",
            "b@example.com",
            "c@example.com",
            "d@example.com",
            "e@example.com",
        ];
        for (i, owner) in owners.iter().enumerate() {
            let (t, org, _) = org_with_routes(&mut req, &mail, owner).await;
            add_recipient(&req, &t, &org, json!({"email": "target@example.com"})).await;
            // Four owners' mails go out unconfirmed; the fifth owner's trips the block.
            assert_eq!(
                mails_to(&mail, "target@example.com"),
                1 + (i + 1).min(4),
                "{owner}"
            );
        }
        let row = blocked(&ctx).await.expect("confirm_blocked row");
        assert!(row.organisation_id.is_none());
        let left = row.expires_at.unwrap() - chrono::Utc::now().fixed_offset();
        assert!(left.num_days() >= 89, "{left}");
        assert_eq!(
            email_suppressions::Entity::find()
                .filter(email_suppressions::Column::Reason.eq("ignored"))
                .count(&ctx.db)
                .await
                .unwrap(),
            0
        );
        // The confirmed recipient still gets deliveries; confirm mails are blocked everywhere.
        let z = organisations::Entity::find()
            .filter(organisations::Column::Slug.eq(&org_z))
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        assert!(guard(&ctx)
            .may_deliver(z.id, "target@example.com", false)
            .await
            .unwrap());
        assert!(!guard(&ctx)
            .may_send_confirm(z.id, "target@example.com")
            .await
            .unwrap());
        // An unsubscribe then replaces the block with a permanent global row.
        let r = recipients::Entity::find()
            .filter(recipients::Column::OrganisationId.eq(z.id))
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        let tok = recipient_service::unsubscribe_token(
            app::state(&ctx).unwrap().config.unsubscribe_key(),
            r.id,
        );
        assert_eq!(
            req.post(&format!("/v1/unsubscribe/{tok}"))
                .await
                .status_code(),
            204
        );
        let row = email_suppressions::Entity::find_by_id(row.id)
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (row.reason.as_str(), row.expires_at),
            ("unsubscribed", None)
        );
        assert!(!guard(&ctx)
            .may_deliver(z.id, "target@example.com", false)
            .await
            .unwrap());
    })
    .await;
}

#[tokio::test]
#[serial]
async fn one_owner_with_five_orgs_sends_two_confirm_mails_per_address() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        let t = sign_in(&req, &mail, "one@example.com").await;
        for i in 0..5 {
            let org = slug(&create_org(&req, &t, &format!("Org {i}")).await);
            let res = add_recipient(&req, &t, &org, json!({"email": "target@example.com"})).await;
            assert_eq!(res.status_code(), 201);
        }
        assert_eq!(mails_to(&mail, "target@example.com"), 2);
        // Withheld silently: no suppression row, no block.
        assert!(blocked(&ctx).await.is_none());
        assert_eq!(
            email_suppressions::Entity::find()
                .filter(email_suppressions::Column::Reason.eq("ignored"))
                .count(&ctx.db)
                .await
                .unwrap(),
            0
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn six_owners_who_each_confirm_never_trip_confirm_blocked() {
    serve(|mut req, ctx| async move {
        let mail = prepare(&ctx);
        let mut first = None;
        for i in 0..6 {
            let (t, org, _) = org_with_routes(&mut req, &mail, &format!("o{i}@example.com")).await;
            first.get_or_insert(org.clone());
            // Each confirms, which clears that owner from the distinct-owner set.
            add_and_confirm(&req, &mail, &t, &org, "target@example.com", &Value::Null).await;
        }
        assert_eq!(mails_to(&mail, "target@example.com"), 6);
        assert!(blocked(&ctx).await.is_none());
        let org = organisations::Entity::find()
            .filter(organisations::Column::Slug.eq(first.unwrap()))
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        assert!(guard(&ctx)
            .may_deliver(org.id, "target@example.com", false)
            .await
            .unwrap());
    })
    .await;
}

#[tokio::test]
#[serial]
async fn confirm_mails_per_address_cap_at_six_a_day_across_orgs() {
    serve(|mut req, ctx| async move {
        let mail = prepare(&ctx);
        // Three owners, two mails each (their own 30-day cap), all confirmed: 6 in one day.
        for owner in ["a@example.com", "b@example.com", "c@example.com"] {
            let (t, org, routes) = org_with_routes(&mut req, &mail, owner).await;
            for r in &routes[..2] {
                add_and_confirm(&req, &mail, &t, &org, "busy@example.com", r).await;
            }
        }
        assert_eq!(mails_to(&mail, "busy@example.com"), 6);
        let (t, org, routes) = org_with_routes(&mut req, &mail, "d@example.com").await;
        add_and_confirm(&req, &mail, &t, &org, "busy@example.com", &routes[0]).await;
        assert_eq!(mails_to(&mail, "busy@example.com"), 6);
        // Confirmed everywhere, so nothing was suppressed.
        assert_eq!(
            email_suppressions::Entity::find()
                .count(&ctx.db)
                .await
                .unwrap(),
            0
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn a_user_creates_at_most_five_orgs_a_day() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        let t = sign_in(&req, &mail, "maker@example.com").await;
        for i in 0..5 {
            create_org(&req, &t, &format!("Org {i}")).await;
        }
        let res = req
            .post("/v1/orgs")
            .add_header("X-CSRF-Token", &t)
            .json(&json!({ "name": "One too many" }))
            .await;
        assert_eq!(res.status_code(), 429);
        assert_eq!(res.json::<Value>()["code"], "rate_limited");
        assert!(res.headers().get("retry-after").is_some());
        assert_eq!(
            organisations::Entity::find().count(&ctx.db).await.unwrap(),
            5
        );
    })
    .await;
}
