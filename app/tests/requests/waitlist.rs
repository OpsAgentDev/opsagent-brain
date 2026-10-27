use opsagent_brain::models::_entities::waitlist_entries;
use sea_orm::{entity::prelude::*, ConnectionTrait};
use serde_json::json;
use serial_test::serial;

use super::support::*;

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
