use chrono::Utc;
use loco_rs::prelude::*;
use opsagent_brain::models::ledger_storage::stmt;
use sea_orm::ConnectionTrait;
use serde_json::Value;
use serial_test::serial;
use uuid::Uuid;

use super::support::*;
use crate::workers::full_scan::{noisy, scan, without_snapshot};

async fn org_id(ctx: &AppContext, conn: Uuid) -> Uuid {
    let r = ctx
        .db
        .query_one_raw(stmt(
            "SELECT organisation_id FROM connections WHERE id = $1",
            vec![conn.into()],
        ))
        .await
        .unwrap()
        .unwrap();
    r.try_get("", "organisation_id").unwrap()
}

async fn deliver(ctx: &AppContext, conn: Uuid, kind: &str, channel: &str, target: &str) -> Uuid {
    let id = Uuid::new_v4();
    ctx.db
        .execute_raw(stmt(
            "INSERT INTO deliveries (id, organisation_id, connection_id, kind, channel, target, \
             status, sent_at) VALUES ($1, $2, $3, $4, $5, $6, 'sent', $7)",
            vec![
                id.into(),
                org_id(ctx, conn).await.into(),
                conn.into(),
                kind.into(),
                channel.into(),
                target.into(),
                Utc::now().into(),
            ],
        ))
        .await
        .unwrap();
    id
}

async fn count(ctx: &AppContext) -> i64 {
    let r = ctx
        .db
        .query_one_raw(stmt("SELECT count(*) AS n FROM deliveries", vec![]))
        .await
        .unwrap()
        .unwrap();
    r.try_get("", "n").unwrap()
}

#[tokio::test]
#[serial]
async fn preview_is_first_scan_then_daily_and_writes_nothing() {
    serve(|req, ctx| async move {
        let (t, org, conn) = connected(&req, &ctx, "o@example.com", "noisy").await;
        let url = format!("/v1/orgs/{org}/connections/{conn}/briefing/preview");
        let none: Value = req.post(&url).add_header("X-CSRF-Token", &t).await.json();
        assert_eq!(
            (none["kind"].as_str(), none["text"].as_str()),
            (Some("none"), Some(""))
        );

        scan(&ctx, conn, 0, &noisy()).await;
        let first: Value = req.post(&url).add_header("X-CSRF-Token", &t).await.json();
        assert_eq!(first["kind"], "first_scan");
        assert!(!first["text"].as_str().unwrap().is_empty());

        deliver(&ctx, conn, "briefing", "slack", "C0").await;
        scan(&ctx, conn, 1, &without_snapshot()).await;
        let daily: Value = req.post(&url).add_header("X-CSRF-Token", &t).await.json();
        assert_eq!(daily["kind"], "daily", "{daily}");
        assert_eq!(count(&ctx).await, 1, "preview wrote no row");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn list_filters_validates_and_hides_addresses() {
    serve(|req, ctx| async move {
        let (_, org, conn) = connected(&req, &ctx, "o@example.com", "noisy").await;
        let id = deliver(&ctx, conn, "briefing", "email", "o@example.com").await;
        deliver(&ctx, conn, "weekly", "slack", "C0SECRET").await;
        let base = format!("/v1/orgs/{org}/deliveries");

        let all = req.get(&base).await;
        assert_eq!(all.status_code(), 200, "{}", all.text());
        let text = all.text();
        assert!(
            !text.contains("o@example.com") && !text.contains("C0SECRET"),
            "{text}"
        );
        let all: Value = all.json();
        assert_eq!(all["items"].as_array().unwrap().len(), 2);
        let mail = all["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["id"] == id.to_string())
            .unwrap();
        assert!(mail["recipient_id"].is_string(), "owner resolved to an id");

        let weekly: Value = req
            .get(&format!("{base}?kind=weekly&connection={conn}"))
            .await
            .json();
        assert_eq!(weekly["items"].as_array().unwrap().len(), 1);
        for q in ["kind=bogus", "connection=nope"] {
            let res = req.get(&format!("{base}?{q}")).await;
            assert_eq!(res.status_code(), 400, "{q}");
            assert_eq!(res.json::<Value>()["code"], "validation");
        }
        let one = req.get(&format!("{base}/{id}")).await;
        assert_eq!(one.status_code(), 200);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn other_orgs_delivery_and_connection_are_404() {
    serve(|req, ctx| async move {
        let (ta, _, conn_a) = connected(&req, &ctx, "a@example.com", "noisy").await;
        let id_a = deliver(&ctx, conn_a, "briefing", "slack", "C0").await;
        sign_out(&req, &ta).await;
        let (t, org_b, _) = connected(&req, &ctx, "b@example.com", "noisy").await;

        let res = req
            .get(&format!("/v1/orgs/{org_b}/deliveries/{id_a}"))
            .await;
        assert_eq!(res.status_code(), 404);
        let list: Value = req
            .get(&format!("/v1/orgs/{org_b}/deliveries"))
            .await
            .json();
        assert!(list["items"].as_array().unwrap().is_empty());
        let res = req
            .post(&format!(
                "/v1/orgs/{org_b}/connections/{conn_a}/briefing/preview"
            ))
            .add_header("X-CSRF-Token", &t)
            .await;
        assert_eq!(res.status_code(), 404);
    })
    .await;
}
