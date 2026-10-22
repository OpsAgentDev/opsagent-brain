use loco_rs::{prelude::*, testing::prelude::request_with_config};
use opsagent_brain::{
    app::App,
    models::_entities::{
        audit_events, connection_credentials, connection_verifications, connections,
    },
};
use serde_json::{json, Value};
use serial_test::serial;

use super::support::*;

const ROLE_ARN: &str = "arn:aws:iam::123456789012:role/OpsAgentReadRole-abcd1234";

fn query_param(url: &str, name: &str) -> String {
    let q = url.split_once('?').unwrap().1;
    let v = q
        .split('&')
        .find_map(|kv| kv.strip_prefix(&format!("{name}=")))
        .unwrap_or_else(|| panic!("{name} missing in {url}"));
    urlencoding::decode(v).unwrap().into_owned()
}

async fn row(ctx: &AppContext, id: &str) -> connections::Model {
    connections::Entity::find_by_id(id.parse::<uuid::Uuid>().unwrap())
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap()
}

async fn audits(ctx: &AppContext, action: &str) -> u64 {
    audit_events::Entity::find()
        .filter(audit_events::Column::Action.eq(action))
        .count(&ctx.db)
        .await
        .unwrap()
}

#[tokio::test]
#[serial]
async fn create_returns_quick_create_url_and_never_shows_external_id_again() {
    request_with_config::<App, _, _>(cookie_config(), |req, ctx| async move {
        let mail = prepare(&ctx);
        let t = sign_in(&req, &mail, "owner@example.com").await;
        let org = slug(&create_org(&req, &t, "Acme").await);
        let c = create_connection(&req, &t, &org, "aws", "Production").await;
        assert_eq!(c["template_version"], "1");
        let url = c["quick_create_url"].as_str().unwrap();
        let ext = query_param(url, "param_ExternalId");
        assert_eq!(uuid::Uuid::parse_str(&ext).unwrap().get_version_num(), 4);
        assert_eq!(
            query_param(url, "templateURL"),
            format!("{TEMPLATE_BASE}/aws/opsagent-read-role-v1.yaml")
        );
        assert_eq!(query_param(url, "param_OpsAgentPrincipal"), OUTBOUND_ARN);
        assert_eq!(query_param(url, "param_TemplateVersion"), "1");
        assert!(query_param(url, "stackName").starts_with("OpsAgent-Read-"));
        let id = c["id"].as_str().unwrap();

        let creds = connection_credentials::Entity::find_by_id(id.parse::<uuid::Uuid>().unwrap())
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        assert!(!String::from_utf8_lossy(&creds.ciphertext).contains(&ext));

        let one = req.get(&format!("/v1/orgs/{org}/connections/{id}")).await;
        assert_eq!(one.status_code(), 200);
        assert_eq!(one.json::<Value>()["status"], "pending");
        let list = req.get(&format!("/v1/orgs/{org}/connections")).await;
        assert_eq!(list.json::<Vec<Value>>().len(), 1);
        let res = verify(&req, &t, &org, id, ROLE_ARN).await;
        assert_eq!(res.status_code(), 202, "{}", res.text());
        for body in [one.text(), list.text(), res.text()] {
            assert!(!body.contains(&ext), "external id leaked: {body}");
        }
        let after = req.get(&format!("/v1/orgs/{org}/connections/{id}")).await;
        assert!(!after.text().contains(&ext));
        assert_eq!(audits(&ctx, "connection.create").await, 1);
        assert_eq!(audits(&ctx, "connection.verify_requested").await, 1);

        let bad = verify(&req, &t, &org, id, "not-an-arn").await;
        assert_eq!(bad.status_code(), 422);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn verify_outcomes_set_status() {
    request_with_config::<App, _, _>(cookie_config(), |mut req, ctx| async move {
        let mail = prepare(&ctx);
        for (i, (account, status)) in [
            ("clean", "connected"),
            ("noisy", "connected"),
            ("blocked", "blocked"),
        ]
        .into_iter()
        .enumerate()
        {
            req.clear_cookies();
            let (t, org, id) = fake_connection(
                &req,
                &mail,
                &format!("o{i}@example.com"),
                &format!("Org {i}"),
                account,
            )
            .await;
            let res = verify(&req, &t, &org, &id, "").await;
            assert_eq!(res.status_code(), 202, "{}", res.text());
            assert!(res.json::<Value>()["run_id"].is_string());
            let body = req
                .get(&format!("/v1/orgs/{org}/connections/{id}"))
                .await
                .json::<Value>();
            assert_eq!(body["status"], status, "{account}: {body}");
            let r = row(&ctx, &id).await;
            if status == "connected" {
                assert_eq!(r.external_account_id.as_deref(), Some(account));
                assert!(r.first_connected_at.is_some() && r.billable_from.is_some());
                assert_eq!(body["last_verification"]["outcome"], "connected");
            } else {
                assert!(r.billable_from.is_none());
                assert!(r.status_reason.unwrap().contains("ec2:TerminateInstances"));
            }
        }
        assert_eq!(
            connection_verifications::Entity::find()
                .count(&ctx.db)
                .await
                .unwrap(),
            3
        );
        assert_eq!(audits(&ctx, "connection.verify_outcome").await, 3);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn same_account_in_second_org_is_409_without_org_names() {
    request_with_config::<App, _, _>(cookie_config(), |mut req, ctx| async move {
        let mail = prepare(&ctx);
        let (ta, oa, ida) =
            fake_connection(&req, &mail, "a@example.com", "Alpha Org", "clean").await;
        assert_eq!(verify(&req, &ta, &oa, &ida, "").await.status_code(), 202);
        req.clear_cookies();
        let (tb, ob, idb) =
            fake_connection(&req, &mail, "b@example.com", "Beta Org", "clean").await;
        let res = verify(&req, &tb, &ob, &idb, "").await;
        assert_eq!(res.status_code(), 409);
        let body = res.text();
        assert_eq!(res.json::<Value>()["code"], "account_already_connected");
        assert!(!body.contains("Alpha") && !body.contains("Beta"), "{body}");
        assert_eq!(row(&ctx, &idb).await.status, "pending");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn cross_org_connection_is_same_404_as_unknown() {
    request_with_config::<App, _, _>(cookie_config(), |mut req, ctx| async move {
        let mail = prepare(&ctx);
        let (_, _, idb) = fake_connection(&req, &mail, "b@example.com", "Org B", "clean").await;
        req.clear_cookies();
        let ta = sign_in(&req, &mail, "a@example.com").await;
        let oa = slug(&create_org(&req, &ta, "Org A").await);
        let res = req.get(&format!("/v1/orgs/{oa}/connections/{idb}")).await;
        let unknown = req
            .get(&format!(
                "/v1/orgs/{oa}/connections/{}",
                uuid::Uuid::new_v4()
            ))
            .await;
        assert_eq!(res.status_code(), 404);
        assert_eq!(unknown.status_code(), 404);
        let (mut x, mut y) = (res.json::<Value>(), unknown.json::<Value>());
        x["instance"] = Value::Null;
        y["instance"] = Value::Null;
        assert_eq!(x, y);
        assert_eq!(verify(&req, &ta, &oa, &idb, "").await.status_code(), 404);
        assert!(req
            .get(&format!("/v1/orgs/{oa}/connections"))
            .await
            .json::<Vec<Value>>()
            .is_empty());
    })
    .await;
}

#[tokio::test]
#[serial]
async fn patch_validates_and_delete_disconnects() {
    request_with_config::<App, _, _>(cookie_config(), |req, ctx| async move {
        let mail = prepare(&ctx);
        let (t, org, id) = fake_connection(&req, &mail, "o@example.com", "Org", "clean").await;
        let url = format!("/v1/orgs/{org}/connections/{id}");
        let res = req
            .patch(&url)
            .add_header("X-CSRF-Token", &t)
            .json(&json!({"scan_time_local": "25:00"}))
            .await;
        assert_eq!(res.status_code(), 422);
        let res = req
            .patch(&url)
            .add_header("X-CSRF-Token", &t)
            .json(&json!({"scan_time_local": "06:30", "briefing_time_local": "08:00", "api_rate_ceiling": 5, "display_name": "Prod"}))
            .await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        let body = res.json::<Value>();
        assert_eq!(body["scan_time_local"], "06:30");
        assert_eq!(body["briefing_time_local"], "08:00");
        assert_eq!(body["api_rate_ceiling"], 5);
        assert_eq!(body["display_name"], "Prod");

        assert_eq!(verify(&req, &t, &org, &id, "").await.status_code(), 202);
        let res = req.delete(&url).add_header("X-CSRF-Token", &t).await;
        assert_eq!(res.status_code(), 200);
        let body = res.json::<Value>();
        assert_eq!(body["status"], "disconnected");
        assert!(body["next_step"].as_str().unwrap().contains("OpsAgent-Read-"));
        assert_eq!(audits(&ctx, "connection.disconnect").await, 1);
        // Row is kept and releases the account.
        assert_eq!(row(&ctx, &id).await.status, "disconnected");

        let res = verify(&req, &t, &org, &id, "").await;
        assert_eq!(res.status_code(), 409);
        assert_eq!(res.json::<Value>()["code"], "connection_disconnected");
    })
    .await;
}
