use loco_rs::{prelude::*, testing::prelude::request_with_config};
use opsagent_brain::{
    app::App,
    models::_entities::{audit_events, connections},
};
use serde_json::Value;
use serial_test::serial;

use super::support::*;
use crate::workers::full_scan::{noisy, scan};

#[tokio::test]
#[serial]
async fn list_and_detail_with_stats() {
    request_with_config::<App, _, _>(cookie_config(), |req, ctx| async move {
        let (_, org, conn) = connected(&req, &ctx, "o@example.com", "noisy").await;
        let run = scan(&ctx, conn, 0, &noisy()).await;
        scan(&ctx, conn, 1, &noisy()).await;

        let list: Value = req
            .get(&format!("/v1/orgs/{org}/runs?type=full_scan&limit=1"))
            .await
            .json();
        assert_eq!(list["items"].as_array().unwrap().len(), 1);
        let cursor = list["next_cursor"].as_str().unwrap();
        let rest: Value = req
            .get(&format!(
                "/v1/orgs/{org}/runs?type=full_scan&cursor={cursor}"
            ))
            .await
            .json();
        assert_eq!(
            rest["items"][0]["id"],
            run.to_string().as_str(),
            "newest first"
        );
        let none: Value = req
            .get(&format!("/v1/orgs/{org}/runs?type=verify"))
            .await
            .json();
        assert_eq!(none["items"].as_array().unwrap().len(), 0);

        let res = req.get(&format!("/v1/orgs/{org}/runs/{run}")).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        let r: Value = res.json();
        assert_eq!(r["status"], "done");
        assert_eq!(r["job_type"], "full_scan");
        assert!(r["stats"]["score"].is_number());
        assert!(r["started_at"].is_string() && r["finished_at"].is_string());
    })
    .await;
}

#[tokio::test]
#[serial]
async fn scan_is_once_per_hour() {
    request_with_config::<App, _, _>(cookie_config(), |req, ctx| async move {
        let (t, org, conn) = connected(&req, &ctx, "o@example.com", "noisy").await;
        let url = format!("/v1/orgs/{org}/connections/{conn}/scan");

        let res = req.post(&url).await;
        assert_eq!(res.status_code(), 403, "csrf required");
        let res = req.post(&url).add_header("X-CSRF-Token", &t).await;
        assert_eq!(res.status_code(), 202, "{}", res.text());
        let run_id = res.json::<Value>()["run_id"].as_str().unwrap().to_owned();
        let r: Value = req
            .get(&format!("/v1/orgs/{org}/runs/{run_id}"))
            .await
            .json();
        assert_eq!(r["job_type"], "full_scan");
        let me: Value = req.get("/v1/auth/me").await.json();
        let audit = audit_events::Entity::find()
            .filter(audit_events::Column::Action.eq("connection.scan_requested"))
            .one(&ctx.db)
            .await
            .unwrap()
            .expect("audit row");
        assert_eq!(audit.actor_type, "member");
        assert_eq!(audit.actor_id.as_deref(), me["id"].as_str());
        assert_eq!(audit.target_type.as_deref(), Some("connection"));
        assert_eq!(audit.target_id, Some(conn.to_string()));

        let res = req.post(&url).add_header("X-CSRF-Token", &t).await;
        assert_eq!(res.status_code(), 429);
        assert_eq!(res.json::<Value>()["code"], "rate_limited");
        let after: u64 = res.header("retry-after").to_str().unwrap().parse().unwrap();
        assert!(after > 3500 && after <= 3600, "{after}");

        let res = req
            .post(&format!(
                "/v1/orgs/{org}/connections/{}/scan",
                uuid::Uuid::new_v4()
            ))
            .add_header("X-CSRF-Token", &t)
            .await;
        assert_eq!(res.status_code(), 404);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn scan_needs_a_connected_or_degraded_connection() {
    request_with_config::<App, _, _>(cookie_config(), |req, ctx| async move {
        let (t, org, conn) = connected(&req, &ctx, "o@example.com", "noisy").await;
        for status in ["blocked", "disconnected", "pending"] {
            let mut a: connections::ActiveModel = connections::Entity::find_by_id(conn)
                .one(&ctx.db)
                .await
                .unwrap()
                .unwrap()
                .into();
            a.status = Set(status.into());
            a.update(&ctx.db).await.unwrap();
            let res = req
                .post(&format!("/v1/orgs/{org}/connections/{conn}/scan"))
                .add_header("X-CSRF-Token", &t)
                .await;
            assert_eq!(res.status_code(), 409, "{status}");
            assert_eq!(res.json::<Value>()["code"], "connection_not_scannable");
        }
        let runs: Value = req.get(&format!("/v1/orgs/{org}/runs")).await.json();
        assert_eq!(runs["items"], serde_json::json!([]));
    })
    .await;
}
