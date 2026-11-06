//! `CloudflareTurnstile` against a wiremock siteverify endpoint, and `NoChallenge`.
use std::time::Duration;

use opsagent_brain::adapters::turnstile::{
    ChallengeError, ChallengeVerifier, CloudflareTurnstile, NoChallenge,
};
use serde_json::json;
use wiremock::{
    matchers::{body_string_contains, header, method, path},
    Mock, MockServer, ResponseTemplate,
};

fn cf(server: &MockServer, timeout: Duration) -> CloudflareTurnstile {
    CloudflareTurnstile::new(&server.uri(), "sec_x", timeout).unwrap()
}

fn verdict(success: bool) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({"success": success}))
}

const T: Duration = Duration::from_secs(5);

#[tokio::test]
async fn valid_token_posts_secret_response_and_ip_as_a_form() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/turnstile/v0/siteverify"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .and(body_string_contains("secret=sec_x"))
        .and(body_string_contains("response=tok_1"))
        .and(body_string_contains("remoteip=203.0.113.9"))
        .respond_with(verdict(true))
        .expect(1)
        .mount(&server)
        .await;
    let ip = "203.0.113.9".parse().ok();
    cf(&server, T).verify(Some("tok_1"), ip).await.unwrap();
}

#[tokio::test]
async fn remoteip_is_omitted_when_unknown() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(|r: &wiremock::Request| !String::from_utf8_lossy(&r.body).contains("remoteip"))
        .respond_with(verdict(true))
        .expect(1)
        .mount(&server)
        .await;
    cf(&server, T).verify(Some("tok_1"), None).await.unwrap();
}

#[tokio::test]
async fn rejected_token_is_failed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(verdict(false))
        .mount(&server)
        .await;
    let r = cf(&server, T).verify(Some("bad"), None).await;
    assert!(matches!(r, Err(ChallengeError::Failed)));
}

#[tokio::test]
async fn missing_or_empty_token_is_failed_without_calling_cloudflare() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(verdict(true))
        .expect(0)
        .mount(&server)
        .await;
    for token in [None, Some(""), Some("  ")] {
        let r = cf(&server, T).verify(token, None).await;
        assert!(matches!(r, Err(ChallengeError::Failed)), "{token:?}");
    }
}

#[tokio::test]
async fn server_error_malformed_body_and_timeout_are_unavailable() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    let r = cf(&server, T).verify(Some("t"), None).await;
    assert!(matches!(r, Err(ChallengeError::Unavailable)));

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html>"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    let r = cf(&server, T).verify(Some("t"), None).await;
    assert!(matches!(r, Err(ChallengeError::Unavailable)));

    Mock::given(method("POST"))
        .respond_with(verdict(true).set_delay(Duration::from_secs(2)))
        .mount(&server)
        .await;
    let r = cf(&server, Duration::from_millis(100))
        .verify(Some("t"), None)
        .await;
    assert!(matches!(r, Err(ChallengeError::Unavailable)));
}

#[tokio::test]
async fn no_challenge_always_passes() {
    NoChallenge.verify(None, None).await.unwrap();
    NoChallenge.verify(Some("x"), None).await.unwrap();
}
