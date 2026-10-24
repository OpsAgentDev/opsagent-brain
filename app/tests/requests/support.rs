use std::sync::Arc;

use axum_test::TestServer;
use opsagent_brain::{
    actions::Actions,
    error::AppResult,
    mailers::{CaptureMailer, Mailer},
    state::AppState,
};
use serde_json::{json, Value};

/// Process environment the app reads at boot; set before every boot.
pub fn test_env() {
    // 32 zero bytes, base64.
    std::env::set_var(
        "OPSAGENT_KEK",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    );
    std::env::set_var("OPSAGENT_CONNECTORS", "fake");
    std::env::set_var("OPSAGENT_TEMPLATE_BASE_URL", TEMPLATE_BASE);
    std::env::set_var("OPSAGENT_AWS_OUTBOUND_ROLE_ARN", OUTBOUND_ARN);
}

pub use crate::support::{serve, serve_with, TestApp};

/// The Redis the app's limiter and leases use.
pub fn redis_of(ctx: &TestApp) -> opsagent_ledger::redis::Client {
    ctx.redis()
}

/// Captures mail and resets the mail limiters, whose counters outlive a test (hours to days).
pub fn prepare(ctx: &TestApp) -> Arc<CaptureMailer> {
    let mut c = redis_of(ctx).get_connection().unwrap();
    let mut keys: Vec<String> = Vec::new();
    for pattern in [
        "ratelimit:magic_link:*",
        "ratelimit:recipient_confirm:*",
        "recipient_confirm:*",
    ] {
        let found: Vec<String> = opsagent_ledger::redis::cmd("KEYS")
            .arg(pattern)
            .query(&mut c)
            .unwrap();
        keys.extend(found);
    }
    if !keys.is_empty() {
        let _: () = opsagent_ledger::redis::cmd("DEL")
            .arg(&keys)
            .query(&mut c)
            .unwrap();
    }
    let mail = Arc::new(CaptureMailer::default());
    let dynamic: Arc<dyn Mailer> = mail.clone();
    ctx.set_mailer(dynamic);
    mail
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

pub async fn sign_out(req: &TestServer, csrf: &str) {
    let res = req
        .post("/v1/auth/sign-out")
        .add_header("X-CSRF-Token", csrf)
        .await;
    assert_eq!(res.status_code(), 204);
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

pub const TEMPLATE_BASE: &str = "https://templates.example.test";
pub const OUTBOUND_ARN: &str = "arn:aws:iam::111111111111:role/opsagent-outbound";

pub fn slug(org: &Value) -> String {
    org["slug"].as_str().unwrap().to_string()
}

/// Creates a connection and returns the 201 body.
pub async fn create_connection(
    req: &TestServer,
    csrf: &str,
    org: &str,
    provider: &str,
    name: &str,
) -> Value {
    let res = req
        .post(&format!("/v1/orgs/{org}/connections"))
        .add_header("X-CSRF-Token", csrf)
        .json(&json!({ "provider": provider, "display_name": name }))
        .await;
    assert_eq!(res.status_code(), 201, "{}", res.text());
    res.json::<Value>()
}

pub async fn verify(
    req: &TestServer,
    csrf: &str,
    org: &str,
    id: &str,
    role_arn: &str,
) -> axum_test::TestResponse {
    req.post(&format!("/v1/orgs/{org}/connections/{id}/verify"))
        .add_header("X-CSRF-Token", csrf)
        .json(&json!({ "role_arn": role_arn }))
        .await
}

/// Owner signs in, creates an org and a fake connection for fixture `account`.
pub async fn fake_connection(
    req: &TestServer,
    mail: &CaptureMailer,
    email: &str,
    org_name: &str,
    account: &str,
) -> (String, String, String) {
    let t = sign_in(req, mail, email).await;
    let org = slug(&create_org(req, &t, org_name).await);
    let c = create_connection(req, &t, &org, "fake", account).await;
    (t, org, c["id"].as_str().unwrap().to_string())
}

/// Owner signs in (email doubles as org name), creates a fake connection for fixture `account`
/// and marks it connected. Returns `(csrf, org slug, connection id)`.
pub async fn connected(
    req: &TestServer,
    ctx: &TestApp,
    email: &str,
    account: &str,
) -> (String, String, uuid::Uuid) {
    use opsagent_brain::models::_entities::connections;
    use sea_orm::{ActiveModelTrait, EntityTrait, Set};
    let mail = prepare(ctx);
    let (t, org, id) = fake_connection(req, &mail, email, email, account).await;
    let id: uuid::Uuid = id.parse().unwrap();
    let mut a: connections::ActiveModel = connections::Entity::find_by_id(id)
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap()
        .into();
    a.status = Set("connected".into());
    a.external_account_id = Set(Some(format!("{account}-{email}")));
    a.update(&ctx.db).await.unwrap();
    (t, org, id)
}

/// Problem body with the per-response `instance` blanked, for byte comparison.
pub fn without_instance(res: &axum_test::TestResponse) -> String {
    let mut v: Value = serde_json::from_str(&res.text()).unwrap();
    v["instance"] = Value::Null;
    v.to_string()
}

/// The booted state.
pub fn state(ctx: &TestApp) -> AppResult<AppState> {
    Ok(ctx.state.clone())
}

/// The actions, built once at boot.
pub fn actions(ctx: &TestApp) -> AppResult<Arc<Actions>> {
    Ok(ctx.state.actions.clone())
}

/// The process KEK (with the DEK cache).
pub fn kek(ctx: &TestApp) -> AppResult<Arc<dyn opsagent_secrets::Kek>> {
    Ok(ctx.state.kek.clone())
}

/// Enqueues one `kind` job for `run_id` and drains the queue, as a worker would run it.
pub async fn perform(
    ctx: &TestApp,
    kind: opsagent_ledger::JobKind,
    run_id: uuid::Uuid,
) -> AppResult<usize> {
    use opsagent_ledger::{NewJob, Queue};
    let run_at = chrono::Utc::now();
    let job = NewJob {
        kind,
        run_id,
        run_at,
    };
    opsagent_brain::adapters::pg_queue::PgQueue(ctx.db.clone())
        .enqueue(job)
        .await?;
    let n = ctx.drain_jobs().await;
    // A job left behind failed (kept for a retry, or dead).
    use sea_orm::ConnectionTrait;
    let q = "SELECT count(*) AS n FROM jobs WHERE run_id = $1";
    let left = ctx
        .db
        .query_one_raw(opsagent_brain::adapters::db::ledger_storage::stmt(
            q,
            vec![run_id.into()],
        ))
        .await
        .map_err(|e| opsagent_brain::error::AppError::Internal(e.to_string()))?
        .and_then(|r| r.try_get::<i64>("", "n").ok());
    match left {
        Some(0) => Ok(n),
        _ => Err(opsagent_brain::error::AppError::Internal(
            "job failed: still queued".into(),
        )),
    }
}
