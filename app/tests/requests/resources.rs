use std::collections::HashSet;

use loco_rs::testing::prelude::request_with_config;
use opsagent_brain::app::App;
use serde_json::Value;
use serial_test::serial;

use super::support::*;
use crate::workers::full_scan::{noisy, scan};

fn ids(page: &Value) -> Vec<String> {
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
#[serial]
async fn list_pages_filters_and_searches() {
    request_with_config::<App, _, _>(cookie_config(), |req, ctx| async move {
        let (_, org, conn) = connected(&req, &ctx, "o@example.com", "noisy").await;
        scan(&ctx, conn, 0, &noisy()).await;
        let base = format!("/v1/orgs/{org}/resources");

        let all: Value = req.get(&format!("{base}?limit=500")).await.json();
        let total = ids(&all).len();
        assert!(total > 2);
        assert_eq!(all["next_cursor"], Value::Null, "500 clamps to 200 > total");

        let first: Value = req.get(&format!("{base}?limit=2")).await.json();
        let cursor = first["next_cursor"].as_str().expect("next_cursor");
        let rest: Value = req
            .get(&format!("{base}?cursor={cursor}&connection={conn}"))
            .await
            .json();
        let seen: HashSet<String> = ids(&first).into_iter().chain(ids(&rest)).collect();
        assert_eq!(seen.len(), total);
        assert_eq!(ids(&first).len() + ids(&rest).len(), total);

        let q: Value = req.get(&format!("{base}?q=SNAP-PUB")).await.json();
        assert_eq!(q["items"][0]["identity"], "snap-public");
        assert_eq!(ids(&q).len(), 1);
        // LIKE wildcards in `q` are literals.
        let wild: Value = req.get(&format!("{base}?q=%25")).await.json();
        assert_eq!(ids(&wild).len(), 0);

        let kind = q["items"][0]["kind"].as_str().unwrap().to_owned();
        let by_kind: Value = req.get(&format!("{base}?kind={kind}")).await.json();
        assert!(by_kind["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["kind"] == kind.as_str()));
    })
    .await;
}
