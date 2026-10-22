//! Slack install, channels, recipients, unsubscribe (Plan 2 Task 9).
use std::sync::Arc;

use axum_test::TestServer;
use loco_rs::{app::AppContext, prelude::*};
use opsagent_brain::{
    adapters::slack::{HttpSlack, SlackClient},
    app::kek,
    mailers::CaptureMailer,
    models::{
        _entities::{audit_events, integrations, organisations, recipients, users},
        integrations::open_token,
        members as member_model,
    },
    services::recipients as recipient_service,
    settings::Settings,
};
use serde_json::{json, Value};
use serial_test::serial;
use wiremock::{
    matchers::{body_string_contains, method, path},
    Mock, MockServer, ResponseTemplate,
};

use super::support::*;

/// Points the app at `slack` and configures Slack client credentials.
fn use_slack(ctx: &AppContext, slack: &MockServer) {
    let mut s = Settings::get(ctx);
    s.slack_client_id = "cid".into();
    s.slack_client_secret = "csecret".into();
    ctx.shared_store.insert(s);
    let c: Arc<dyn SlackClient> = Arc::new(HttpSlack::new(slack.uri()));
    ctx.shared_store.insert(c);
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
    member_model::add(&ctx.db, o.id, user.id, "member")
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
        let plain = open_token(&ctx.db, kek(&ctx).unwrap().as_ref(), &row)
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
async fn unsubscribe_token_is_single_use_and_owner_deletes() {
    serve(|req, ctx| async move {
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
        let token =
            recipient_service::issue_unsubscribe_token(&ctx.db, row.organisation_id, row.id)
                .await
                .unwrap();
        let res = req.post(&format!("/v1/unsubscribe/{token}")).await;
        assert_eq!(res.status_code(), 204);
        assert_eq!(
            req.post(&format!("/v1/unsubscribe/{token}"))
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
