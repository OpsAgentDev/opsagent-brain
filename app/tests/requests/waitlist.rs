use opsagent_brain::models::_entities::waitlist_entries;
use sea_orm::{entity::prelude::*, ConnectionTrait};
use serde_json::json;
use serial_test::serial;

use std::sync::{Arc, Mutex};

use opsagent_brain::mailers::{Mail, Mailer};

use super::support::*;

struct FailingMailer;

#[async_trait::async_trait]
impl Mailer for FailingMailer {
    async fn send(&self, _: Mail) -> Result<(), String> {
        Err("boom".into())
    }
}

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

async fn until(mut done: impl FnMut() -> bool) {
    for _ in 0..300 {
        if done() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("timed out waiting");
}

/// Empty table and fresh IP counters: both outlive a test.
async fn reset(ctx: &TestApp) {
    ctx.db
        .execute_unprepared("TRUNCATE waitlist_entries")
        .await
        .unwrap();
    let mut c = redis_of(ctx).get_connection().unwrap();
    let keys: Vec<String> = opsagent_ledger::redis::cmd("KEYS")
        .arg("waitlist:*")
        .query(&mut c)
        .unwrap();
    if !keys.is_empty() {
        let _: () = opsagent_ledger::redis::cmd("DEL")
            .arg(&keys)
            .query(&mut c)
            .unwrap();
    }
}

#[tokio::test]
#[serial]
async fn new_email_is_accepted() {
    serve(|req, ctx| async move {
        reset(&ctx).await;
        let res = req
            .post("/v1/waitlist")
            .json(&json!({"email":"a@b.io"}))
            .await;
        assert_eq!(res.status_code(), 202);
        let rows = waitlist_entries::Entity::find().all(&ctx.db).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].email, "a@b.io");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn duplicate_after_normalising_is_accepted_once() {
    serve(|req, ctx| async move {
        reset(&ctx).await;
        for email in [" A@B.io ", "a@b.io"] {
            let res = req
                .post("/v1/waitlist")
                .json(&json!({ "email": email }))
                .await;
            assert_eq!(res.status_code(), 202);
        }
        assert_eq!(
            waitlist_entries::Entity::find()
                .count(&ctx.db)
                .await
                .unwrap(),
            1
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn invalid_email_is_422() {
    serve(|req, ctx| async move {
        reset(&ctx).await;
        let res = req
            .post("/v1/waitlist")
            .json(&json!({"email":"no-at-sign"}))
            .await;
        assert_eq!(res.status_code(), 422);
        assert_eq!(
            waitlist_entries::Entity::find()
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
async fn source_over_64_chars_is_422() {
    serve(|req, ctx| async move {
        reset(&ctx).await;
        let ok = req
            .post("/v1/waitlist")
            .json(&json!({"email":"a@b.io","source":"s".repeat(64)}))
            .await;
        assert_eq!(ok.status_code(), 202);
        let res = req
            .post("/v1/waitlist")
            .json(&json!({"email":"c@d.io","source":"s".repeat(65)}))
            .await;
        assert_eq!(res.status_code(), 422);
        assert_eq!(
            waitlist_entries::Entity::find()
                .count(&ctx.db)
                .await
                .unwrap(),
            1
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn ip_limit_returns_429() {
    serve(|req, ctx| async move {
        reset(&ctx).await;
        let post = |ip: &'static str| {
            req.post("/v1/waitlist")
                .add_header("x-forwarded-for", ip)
                .json(&json!({"email":"a@b.io"}))
        };
        for _ in 0..10 {
            assert_eq!(post("198.51.100.20").await.status_code(), 202);
        }
        let res = post("198.51.100.20").await;
        assert_eq!(res.status_code(), 429);
        assert_eq!(res.header("retry-after"), "3600");
        // Another address is unaffected.
        assert_eq!(post("198.51.100.21").await.status_code(), 202);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn no_csrf_needed_anonymously() {
    serve(|req, ctx| async move {
        reset(&ctx).await;
        let res = req
            .post("/v1/waitlist")
            .json(&json!({"email":"x@y.io"}))
            .await;
        assert_eq!(res.status_code(), 202);
        assert!(res.text().is_empty());
    })
    .await;
}

#[tokio::test]
#[serial]
async fn new_email_gets_one_confirmation() {
    serve(|req, ctx| async move {
        reset(&ctx).await;
        let mail = prepare(&ctx);
        let res = req
            .post("/v1/waitlist")
            .json(&json!({"email":"a@b.io"}))
            .await;
        assert_eq!(res.status_code(), 202);
        until(|| !mail.sent().is_empty()).await;
        let sent = mail.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].to, "a@b.io");
        assert_eq!(sent[0].subject, "You're on the OpsAgent waitlist");
        for _ in 0..300 {
            let row = waitlist_entries::Entity::find().one(&ctx.db).await.unwrap();
            if row.unwrap().confirmation_sent_at.is_some() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("confirmation_sent_at never set");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn duplicate_sends_no_second_mail() {
    serve(|req, ctx| async move {
        reset(&ctx).await;
        let mail = prepare(&ctx);
        for _ in 0..2 {
            let res = req
                .post("/v1/waitlist")
                .json(&json!({"email":"a@b.io"}))
                .await;
            assert_eq!(res.status_code(), 202);
        }
        until(|| !mail.sent().is_empty()).await;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(mail.sent().len(), 1);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn concurrent_duplicates_send_one_mail() {
    serve(|req, ctx| async move {
        reset(&ctx).await;
        let mail = prepare(&ctx);
        let post = || req.post("/v1/waitlist").json(&json!({"email":"a@b.io"}));
        let (a, b) = tokio::join!(post(), post());
        assert_eq!(
            (a.status_code().as_u16(), b.status_code().as_u16()),
            (202, 202)
        );
        assert_eq!(mail.sent().len(), 1);
        assert_eq!(
            waitlist_entries::Entity::find()
                .count(&ctx.db)
                .await
                .unwrap(),
            1
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn mail_failure_still_accepts() {
    let buf = Buf::default();
    let sub = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .with_writer({
            let b = buf.clone();
            move || b.clone()
        })
        .finish();
    let _g = tracing::subscriber::set_default(sub);
    serve(|req, ctx| async move {
        reset(&ctx).await;
        ctx.set_mailer(Arc::new(FailingMailer));
        let res = req
            .post("/v1/waitlist")
            .json(&json!({"email":"a@b.io"}))
            .await;
        assert_eq!(res.status_code(), 202);
        // Wait for the background send to fail and log before reading.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let row = waitlist_entries::Entity::find().one(&ctx.db).await.unwrap();
        assert!(row.unwrap().confirmation_sent_at.is_none());
    })
    .await;
    let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(out.contains("waitlist confirmation not sent"), "{out}");
    assert!(!out.contains("a@b.io"), "{out}");
}
