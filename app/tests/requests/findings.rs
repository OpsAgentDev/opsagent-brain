use std::collections::HashSet;

use chrono::{Duration, Utc};
use loco_rs::prelude::*;
use opsagent_brain::models::_entities::{audit_events, finding_events, findings};
use serde_json::{json, Value};
use serial_test::serial;

use super::support::*;
use crate::workers::full_scan::{expected, noisy, scan};

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
    serve(|req, ctx| async move {
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
        let want = expected().await;
        assert_eq!(ids(&first).len() + ids(&rest).len(), want.len());
        assert_eq!(all.len(), want.len(), "pages overlap");

        let crit: Value = req
            .get(&format!("{base}?severity=critical&connection={conn}"))
            .await
            .json();
        let n_crit = want.iter().filter(|f| f.3 == "critical").count();
        assert_eq!(ids(&crit).len(), n_crit);
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
    serve(|req, ctx| async move {
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
async fn accept_snooze_reopen_and_report() {
    serve(|req, ctx| async move {
        let (t, org, conn) = connected(&req, &ctx, "o@example.com", "noisy").await;
        scan(&ctx, conn, 0, &noisy()).await;
        let id = finding_id(&ctx, "sg-ssh").await;
        let url = |a: &str| format!("/v1/orgs/{org}/findings/{id}/{a}");
        let post =
            |a: &str, body: Value| req.post(&url(a)).add_header("X-CSRF-Token", &t).json(&body);

        let res = req.post(&url("accept")).json(&json!({"reason": "x"})).await;
        assert_eq!(res.status_code(), 403, "csrf required");
        let res = post("accept", json!({})).await;
        assert_eq!(res.status_code(), 422);
        assert_eq!(res.json::<Value>()["code"], "validation");
        let res = post("accept", json!({"reason": "  "})).await;
        assert_eq!(res.status_code(), 422);
        let far = (Utc::now() + Duration::days(366)).to_rfc3339();
        let res = post("accept", json!({"reason": "ok", "until": far})).await;
        assert_eq!(res.status_code(), 422);

        let res = post("accept", json!({"reason": "lab box"})).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        let f: Value = res.json();
        assert_eq!(f["status"], "accepted");
        assert_eq!(f["accepted_reason"], "lab box");
        let until: chrono::DateTime<Utc> = f["accepted_until"].as_str().unwrap().parse().unwrap();
        assert!(
            (until - (Utc::now() + Duration::days(90)))
                .num_minutes()
                .abs()
                < 5
        );

        let d31 = (Utc::now() + Duration::days(31)).to_rfc3339();
        let res = post("snooze", json!({"until": d31})).await;
        assert_eq!(res.status_code(), 422);
        let d7 = (Utc::now() + Duration::days(7)).to_rfc3339();
        let res = post("snooze", json!({"until": d7})).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        assert_eq!(res.json::<Value>()["status"], "snoozed");

        let res = post("reopen", json!({})).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        let f: Value = res.json();
        assert_eq!(f["status"], "open");
        assert_eq!(f["snoozed_until"], Value::Null);

        let mut kinds: Vec<String> = finding_events::Entity::find()
            .filter(finding_events::Column::FindingId.eq(id.parse::<uuid::Uuid>().unwrap()))
            .all(&ctx.db)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.event_type)
            .collect();
        kinds.sort();
        assert_eq!(kinds, ["accepted", "opened", "reopened", "snoozed"]);

        let res = post("report-explanation", json!({"note": "wrong"})).await;
        assert_eq!(res.status_code(), 204);
        let n = audit_events::Entity::find()
            .filter(audit_events::Column::Action.eq("finding.report_explanation"))
            .count(&ctx.db)
            .await
            .unwrap();
        assert_eq!(n, 1);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn other_orgs_finding_is_the_same_404_as_unknown() {
    serve(|req, ctx| async move {
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
        let res = req
            .post(&format!("/v1/orgs/{org_a}/findings/{id_b}/accept"))
            .add_header("X-CSRF-Token", &t)
            .json(&json!({"reason": "mine now"}))
            .await;
        assert_eq!(res.status_code(), 404);
        let list: Value = req.get(&format!("/v1/orgs/{org_a}/findings")).await.json();
        assert_eq!(list["items"], json!([]));
    })
    .await;
}
