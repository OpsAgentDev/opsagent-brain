use opsagent_brain::models::_entities::contact_messages;
use sea_orm::{entity::prelude::*, ConnectionTrait};
use serde_json::{json, Value};
use serial_test::serial;

use std::sync::{Arc, Mutex};

use super::support::*;

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

/// Empty table and fresh counters: both outlive a test.
async fn reset(ctx: &TestApp) {
    ctx.db
        .execute_unprepared("TRUNCATE contact_messages")
        .await
        .unwrap();
    let mut c = redis_of(ctx).get_connection().unwrap();
    let keys: Vec<String> = opsagent_ledger::redis::cmd("KEYS")
        .arg("contact:*")
        .query(&mut c)
        .unwrap();
    if !keys.is_empty() {
        let _: () = opsagent_ledger::redis::cmd("DEL")
            .arg(&keys)
            .query(&mut c)
            .unwrap();
    }
}

fn body() -> Value {
    json!({"name":"Ann Visitor","email":"ann@visitor.io","topic":"security","message":"Please call me about the audit."})
}

#[tokio::test]
#[serial]
async fn valid_message_is_saved_and_forwarded() {
    serve(|req, ctx| async move {
        reset(&ctx).await;
        let mail = prepare(&ctx);
        let res = req.post("/v1/contact").json(&body()).await;
        assert_eq!(res.status_code(), 202);
        assert!(res.text().is_empty());
        until(|| !mail.sent().is_empty()).await;
        let sent = mail.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].to, "info@opsagent.dev");
        assert_eq!(sent[0].reply_to.as_deref(), Some("ann@visitor.io"));
        assert_eq!(sent[0].subject, "[Contact/Security] Ann Visitor");
        for _ in 0..300 {
            let rows = contact_messages::Entity::find().all(&ctx.db).await.unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].email, "ann@visitor.io");
            assert_eq!(rows[0].topic, "security");
            if rows[0].forwarded_at.is_some() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("forwarded_at never set");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn honeypot_is_202_with_nothing_saved_or_sent() {
    serve(|req, ctx| async move {
        reset(&ctx).await;
        let mail = prepare(&ctx);
        let mut b = body();
        b["website"] = json!("http://spam.example");
        let res = req.post("/v1/contact").json(&b).await;
        assert_eq!(res.status_code(), 202);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(
            contact_messages::Entity::find()
                .count(&ctx.db)
                .await
                .unwrap(),
            0
        );
        assert!(mail.sent().is_empty());
    })
    .await;
}

#[tokio::test]
#[serial]
async fn each_invalid_field_is_422() {
    serve(|req, ctx| async move {
        reset(&ctx).await;
        let mail = prepare(&ctx);
        for (field, value) in [
            ("email", "no-at-sign"),
            ("topic", "billing"),
            ("message", "too short"),
            ("name", "   "),
        ] {
            let mut b = body();
            b[field] = json!(value);
            let res = req.post("/v1/contact").json(&b).await;
            assert_eq!(res.status_code(), 422, "{field}");
        }
        assert_eq!(
            contact_messages::Entity::find()
                .count(&ctx.db)
                .await
                .unwrap(),
            0
        );
        assert!(mail.sent().is_empty());
    })
    .await;
}

#[tokio::test]
#[serial]
async fn sixth_request_from_one_ip_is_429() {
    serve(|req, ctx| async move {
        reset(&ctx).await;
        prepare(&ctx);
        let post = |ip: &'static str| {
            req.post("/v1/contact")
                .add_header("x-forwarded-for", ip)
                .json(&body())
        };
        for _ in 0..5 {
            assert_eq!(post("198.51.100.30").await.status_code(), 202);
        }
        let res = post("198.51.100.30").await;
        assert_eq!(res.status_code(), 429);
        assert_eq!(res.header("retry-after"), "3600");
        assert_eq!(post("198.51.100.31").await.status_code(), 202);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn logs_never_hold_the_email_or_message() {
    let buf = Buf::default();
    let sub = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer({
            let b = buf.clone();
            move || b.clone()
        })
        .finish();
    let _g = tracing::subscriber::set_default(sub);
    serve(|req, ctx| async move {
        reset(&ctx).await;
        let mail = prepare(&ctx);
        let res = req.post("/v1/contact").json(&body()).await;
        assert_eq!(res.status_code(), 202);
        until(|| !mail.sent().is_empty()).await;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    })
    .await;
    let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(out.contains("contact message saved"), "{out}");
    assert!(!out.contains("ann@visitor.io"), "{out}");
    assert!(!out.contains("call me about the audit"), "{out}");
}
