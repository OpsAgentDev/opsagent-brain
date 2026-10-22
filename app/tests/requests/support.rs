use std::sync::Arc;

use axum_test::TestServer;
use loco_rs::{app::AppContext, testing::prelude::*};
use opsagent_brain::mailers::{CaptureMailer, Mailer};
use serde_json::{json, Value};

pub fn prepare(ctx: &AppContext) -> Arc<CaptureMailer> {
    // 32 zero bytes, base64.
    std::env::set_var(
        "OPSAGENT_KEK",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    );
    let mail = Arc::new(CaptureMailer::default());
    let dynamic: Arc<dyn Mailer> = mail.clone();
    ctx.shared_store.insert(dynamic);
    mail
}

pub fn cookie_config() -> RequestConfig {
    RequestConfigBuilder::new().save_cookies(true).build()
}

/// Last captured URL (the link in the mail body).
pub fn last_link(mail: &CaptureMailer) -> String {
    let m = mail.sent().pop().expect("no mail sent");
    m.text
        .split_whitespace()
        .find(|w| w.starts_with("http"))
        .expect("no link in mail")
        .to_string()
}

pub const WEB_ORIGIN: &str = "http://localhost:3000";

pub fn token_of(link: &str) -> String {
    link.rsplit(['=', '/']).next().unwrap().to_string()
}

pub async fn redeem(req: &TestServer, token: &str) -> axum_test::TestResponse {
    req.post("/v1/auth/magic-link/redeem")
        .add_header("Origin", WEB_ORIGIN)
        .json(&json!({ "token": token }))
        .await
}

/// Full magic-link sign-in; returns the CSRF token for the new session.
pub async fn sign_in(req: &TestServer, mail: &CaptureMailer, email: &str) -> String {
    let res = req
        .post("/v1/auth/magic-link")
        .json(&json!({ "email": email }))
        .await;
    assert_eq!(res.status_code(), 202);
    let res = redeem(req, &token_of(&last_link(mail))).await;
    assert_eq!(res.status_code(), 200);
    csrf(req).await
}

pub async fn csrf(req: &TestServer) -> String {
    let res = req.get("/v1/auth/csrf").await;
    assert_eq!(res.status_code(), 200);
    res.json::<Value>()["token"].as_str().unwrap().to_string()
}

pub async fn create_org(req: &TestServer, csrf: &str, name: &str) -> Value {
    let res = req
        .post("/v1/orgs")
        .add_header("X-CSRF-Token", csrf)
        .json(&json!({ "name": name }))
        .await;
    assert_eq!(res.status_code(), 201, "{}", res.text());
    res.json::<Value>()
}
