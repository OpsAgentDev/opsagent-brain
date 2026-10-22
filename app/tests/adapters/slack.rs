//! `HttpSlack` against a wiremock Slack Web API.
use opsagent_brain::adapters::slack::{HttpSlack, SlackClient, SlackError};
use serde_json::json;
use wiremock::{
    matchers::{body_partial_json, body_string_contains, header, method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

fn ok(body: serde_json::Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(body)
}

async fn post_error(template: ResponseTemplate) -> SlackError {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(template)
        .mount(&server)
        .await;
    HttpSlack::new(server.uri())
        .post_message("xoxb-t", "C1", "hi", "run:key")
        .await
        .unwrap_err()
}

#[tokio::test]
async fn post_message_sends_token_and_client_msg_id_and_returns_ts() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .and(header("authorization", "Bearer xoxb-t"))
        .and(body_partial_json(
            json!({"channel": "C1", "text": "hi", "client_msg_id": "run:key"}),
        ))
        .respond_with(ok(json!({"ok": true, "ts": "1700000000.000100"})))
        .expect(1)
        .mount(&server)
        .await;
    let ts = HttpSlack::new(server.uri())
        .post_message("xoxb-t", "C1", "hi", "run:key")
        .await
        .unwrap();
    assert_eq!(ts, "1700000000.000100");
}

#[tokio::test]
async fn post_message_maps_slack_error_codes() {
    let err = |code: &str| ok(json!({"ok": false, "error": code}));
    assert_eq!(post_error(err("token_revoked")).await, SlackError::Revoked);
    assert_eq!(post_error(err("invalid_auth")).await, SlackError::Revoked);
    assert_eq!(
        post_error(err("channel_not_found")).await,
        SlackError::ChannelGone
    );
    assert_eq!(
        post_error(err("is_archived")).await,
        SlackError::ChannelGone
    );
    assert_eq!(
        post_error(err("msg_too_long")).await,
        SlackError::Other("msg_too_long".into())
    );
    assert_eq!(
        post_error(ResponseTemplate::new(500)).await,
        SlackError::Other("http_500".into())
    );
}

#[tokio::test]
async fn ratelimited_carries_retry_after() {
    let limited = ResponseTemplate::new(429)
        .insert_header("Retry-After", "30")
        .set_body_json(json!({"ok": false, "error": "ratelimited"}));
    assert_eq!(post_error(limited).await, SlackError::RateLimited(30));
}

#[tokio::test]
async fn channels_follow_cursor_public_and_private_unarchived() {
    let server = MockServer::start().await;
    let page = |ids: &[&str], next: &str| {
        let chans: Vec<_> = ids
            .iter()
            .map(|i| json!({"id": i, "name": format!("n-{i}")}))
            .collect();
        ok(json!({"ok": true, "channels": chans, "response_metadata": {"next_cursor": next}}))
    };
    Mock::given(method("GET"))
        .and(path("/conversations.list"))
        .and(query_param("cursor", "c2"))
        .respond_with(page(&["G2"], ""))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/conversations.list"))
        .and(header("authorization", "Bearer xoxb-t"))
        .and(query_param("types", "public_channel,private_channel"))
        .and(query_param("exclude_archived", "true"))
        .respond_with(page(&["C1"], "c2"))
        .mount(&server)
        .await;
    let chans = HttpSlack::new(server.uri())
        .channels("xoxb-t")
        .await
        .unwrap();
    let ids: Vec<_> = chans
        .iter()
        .map(|c| (c.id.as_str(), c.name.as_str()))
        .collect();
    assert_eq!(ids, [("C1", "n-C1"), ("G2", "n-G2")]);
}

#[tokio::test]
async fn channels_stop_at_1000() {
    let server = MockServer::start().await;
    let chans: Vec<_> = (0..200)
        .map(|i| json!({"id": format!("C{i}"), "name": "x"}))
        .collect();
    Mock::given(method("GET"))
        .and(path("/conversations.list"))
        .respond_with(ok(
            json!({"ok": true, "channels": chans, "response_metadata": {"next_cursor": "more"}}),
        ))
        .expect(5)
        .mount(&server)
        .await;
    let got = HttpSlack::new(server.uri())
        .channels("xoxb-t")
        .await
        .unwrap();
    assert_eq!(got.len(), 1000);
}

#[tokio::test]
async fn oauth_access_returns_install_or_error_code() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth.v2.access"))
        .and(body_string_contains("code=good"))
        .and(body_string_contains("client_id=cid"))
        .respond_with(ok(json!({
            "ok": true, "access_token": "xoxb-new", "token_type": "bot",
            "scope": "chat:write,channels:read", "bot_user_id": "U0BOT",
            "team": {"id": "T1", "name": "Acme"}
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth.v2.access"))
        .respond_with(ok(json!({"ok": false, "error": "invalid_code"})))
        .mount(&server)
        .await;
    let slack = HttpSlack::new(server.uri());
    let i = slack
        .oauth_access("cid", "secret", "good", "https://api.test/cb")
        .await
        .unwrap();
    assert_eq!(i.access_token, "xoxb-new");
    assert_eq!((i.team_id.as_str(), i.team_name.as_str()), ("T1", "Acme"));
    assert_eq!(i.bot_user_id, "U0BOT");
    assert_eq!(i.scope, "chat:write,channels:read");
    let err = slack
        .oauth_access("cid", "secret", "bad", "https://api.test/cb")
        .await
        .err()
        .unwrap();
    assert_eq!(err, SlackError::Other("invalid_code".into()));
}
