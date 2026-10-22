use std::collections::HashSet;

use loco_rs::{prelude::*, testing::prelude::request_with_config};
use opsagent_brain::{app::App, models::_entities::findings};
use serde_json::{json, Value};
use serial_test::serial;

use super::support::*;
use crate::workers::full_scan::{noisy, scan};

async fn finding_id(ctx: &AppContext, identity: &str) -> String {
    findings::Entity::find()
        .filter(findings::Column::ResourceIdentity.eq(identity))
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap()
        .id
        .to_string()
}

fn ids(page: &Value) -> Vec<String> {
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
#[serial]
async fn list_pages_with_cursor_and_filters() {
    request_with_config::<App, _, _>(cookie_config(), |req, ctx| async move {
        let (_, org, conn) = connected(&req, &ctx, "o@example.com", "noisy").await;
        scan(&ctx, conn, 0, &noisy()).await;
        let base = format!("/v1/orgs/{org}/findings");

        let first = req.get(&format!("{base}?limit=2")).await;
        assert_eq!(first.status_code(), 200, "{}", first.text());
        let first: Value = first.json();
        assert_eq!(ids(&first).len(), 2);
        let cursor = first["next_cursor"]
            .as_str()
            .expect("next_cursor")
            .to_owned();
        let rest: Value = req
            .get(&format!("{base}?limit=200&cursor={cursor}"))
            .await
            .json();
        assert_eq!(rest["next_cursor"], Value::Null);
        let all: HashSet<String> = ids(&first).into_iter().chain(ids(&rest)).collect();
        assert_eq!(ids(&first).len() + ids(&rest).len(), 15);
        assert_eq!(all.len(), 15, "pages overlap");

        let crit: Value = req
            .get(&format!("{base}?severity=critical&connection={conn}"))
            .await
            .json();
        assert_eq!(ids(&crit).len(), 2);
        let iam: Value = req.get(&format!("{base}?check=02")).await.json();
        assert_eq!(ids(&iam).len(), 3, "admin_user, key_over_90d, no_mfa");
        let accepted: Value = req.get(&format!("{base}?status=accepted")).await.json();
        assert_eq!(ids(&accepted).len(), 0);

        let res = req.get(&format!("{base}?cursor=garbage")).await;
        assert_eq!(res.status_code(), 422);
        assert_eq!(res.json::<Value>()["code"], "validation");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn detail_has_evidence_and_events() {
    request_with_config::<App, _, _>(cookie_config(), |req, ctx| async move {
        let (_, org, conn) = connected(&req, &ctx, "o@example.com", "noisy").await;
        scan(&ctx, conn, 0, &noisy()).await;
        let id = finding_id(&ctx, "sg-ssh").await;
        let res = req.get(&format!("/v1/orgs/{org}/findings/{id}")).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        let f: Value = res.json();
        assert_eq!(f["id"], id.as_str());
        assert_eq!(f["severity"], "critical");
        assert!(!f["evidence"].as_array().unwrap().is_empty());
        assert_eq!(f["events"][0]["event_type"], "opened");
        assert_eq!(f["explanation"], Value::Null);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn other_orgs_finding_is_the_same_404_as_unknown() {
    request_with_config::<App, _, _>(cookie_config(), |req, ctx| async move {
        let (tb, _, conn_b) = connected(&req, &ctx, "b@example.com", "noisy").await;
        scan(&ctx, conn_b, 0, &noisy()).await;
        let id_b = finding_id(&ctx, "sg-ssh").await;

        let mail = prepare(&ctx);
        sign_out(&req, &tb).await;
        let t = sign_in(&req, &mail, "a@example.com").await;
        let org_a = slug(&create_org(&req, &t, "A").await);
        let theirs = req.get(&format!("/v1/orgs/{org_a}/findings/{id_b}")).await;
        let unknown = req
            .get(&format!(
                "/v1/orgs/{org_a}/findings/{}",
                uuid::Uuid::new_v4()
            ))
            .await;
        assert_eq!(theirs.status_code(), 404);
        assert_eq!(without_instance(&theirs), without_instance(&unknown));
        let list: Value = req.get(&format!("/v1/orgs/{org_a}/findings")).await.json();
        assert_eq!(list["items"], json!([]));
    })
    .await;
}
