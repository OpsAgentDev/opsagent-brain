use loco_rs::testing::prelude::request_with_config;
use opsagent_brain::app::App;
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
