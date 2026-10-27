use opsagent_brain::{
    actions::uow::Repos,
    adapters::db::Pg,
    models::_entities::{
        audit_events, connection_credentials, connection_verifications, connections,
    },
};
use opsagent_core::connection::ConnectionStatus as S;
use sea_orm::{entity::prelude::*, Set};
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

async fn row(ctx: &TestApp, id: &str) -> connections::Model {
    connections::Entity::find_by_id(id.parse::<uuid::Uuid>().unwrap())
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap()
}

async fn audits(ctx: &TestApp, action: &str) -> u64 {
    audit_events::Entity::find()
        .filter(audit_events::Column::Action.eq(action))
        .count(&ctx.db)
        .await
        .unwrap()
}

#[tokio::test]
#[serial]
async fn create_returns_quick_create_url_and_never_shows_external_id_again() {
    serve(|req, ctx| async move {
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
    serve(|mut req, ctx| async move {
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
async fn same_account_in_second_org_is_blocked_by_worker_without_org_names() {
    serve(|mut req, ctx| async move {
        let mail = prepare(&ctx);
        let (ta, oa, ida) =
            fake_connection(&req, &mail, "a@example.com", "Alpha Org", "clean").await;
        assert_eq!(verify(&req, &ta, &oa, &ida, "").await.status_code(), 202);
        assert_eq!(row(&ctx, &ida).await.status, "connected");
        req.clear_cookies();
        let (tb, ob, idb) =
            fake_connection(&req, &mail, "b@example.com", "Beta Org", "clean").await;
        let res = verify(&req, &tb, &ob, &idb, "").await;
        assert_eq!(res.status_code(), 202, "{}", res.text());
        let b = row(&ctx, &idb).await;
        assert_eq!(b.status, "blocked");
        assert_eq!(
            b.status_reason.as_deref(),
            Some("account_already_connected")
        );
        let body = req
            .get(&format!("/v1/orgs/{ob}/connections/{idb}"))
            .await
            .text();
        assert!(
            !body.contains("Alpha") && !body.contains("Beta Org"),
            "{body}"
        );
        assert_eq!(row(&ctx, &ida).await.status, "connected");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn status_cas_refuses_a_stale_read() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        let (t, org, id) = fake_connection(&req, &mail, "o@example.com", "Org", "clean").await;
        let stale = row(&ctx, &id).await; // read as pending
        let (org_id, conn_id) = (stale.organisation_id, stale.id);
        let res = req
            .delete(&format!("/v1/orgs/{org}/connections/{id}"))
            .add_header("X-CSRF-Token", &t)
            .await;
        assert_eq!(res.status_code(), 200);
        let repo = Pg::new(&ctx.db);
        let cas = |from, to| {
            repo.connections()
                .cas_status(org_id, conn_id, from, to, None)
        };
        assert!(!cas(S::Pending, S::Verifying).await.unwrap());
        assert_eq!(row(&ctx, &id).await.status, "disconnected");
        assert!(cas(S::Disconnected, S::Disconnected).await.unwrap());
    })
    .await;
}

#[tokio::test]
#[serial]
async fn cross_org_connection_is_same_404_as_unknown() {
    serve(|mut req, ctx| async move {
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
    serve(|req, ctx| async move {
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

#[tokio::test]
#[serial]
async fn changing_the_role_of_a_live_connection_needs_a_reconnect() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        let t = sign_in(&req, &mail, "owner@example.com").await;
        let org = slug(&create_org(&req, &t, "Acme").await);
        let c = create_connection(&req, &t, &org, "aws", "Production").await;
        let id = c["id"].as_str().unwrap();
        assert_eq!(
            verify(&req, &t, &org, id, ROLE_ARN).await.status_code(),
            202
        );
        let other = "arn:aws:iam::123456789012:role/SomeoneElsesRole";
        for status in ["connected", "degraded"] {
            let mut a: connections::ActiveModel = row(&ctx, id).await.into();
            a.status = Set(status.into());
            a.external_account_id = Set(Some("123456789012".into()));
            a.update(&ctx.db).await.unwrap();
            let res = verify(&req, &t, &org, id, other).await;
            assert_eq!(res.status_code(), 409, "{status}");
            assert_eq!(
                res.json::<Value>()["code"],
                "role_change_requires_reconnect"
            );
            let kek = kek(&ctx).unwrap();
            let org_id = row(&ctx, id).await.organisation_id;
            let conn_id = id.parse().unwrap();
            let creds =
                opsagent_brain::creds::load(&Pg::new(&ctx.db), kek.as_ref(), org_id, conn_id)
                    .await
                    .unwrap();
            assert_eq!(creds.role_arn.as_deref(), Some(ROLE_ARN), "{status}");
            assert_eq!(row(&ctx, id).await.status, status);
        }
        // Re-verifying the same role stays allowed.
        assert_eq!(
            verify(&req, &t, &org, id, ROLE_ARN).await.status_code(),
            202
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn new_scan_time_moves_the_nightly_scan_from_tomorrow() {
    use opsagent_brain::models::_entities::schedules;
    use opsagent_deliver::schedule::{end_of_local_day, next_after};
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        let (t, org, id) = fake_connection(&req, &mail, "o@example.com", "Org", "clean").await;
        assert_eq!(verify(&req, &t, &org, &id, "").await.status_code(), 202);
        let res = req
            .patch(&format!("/v1/orgs/{org}/connections/{id}"))
            .add_header("X-CSRF-Token", &t)
            .json(&json!({"scan_time_local": "06:30"}))
            .await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        let s = schedules::Entity::find()
            .filter(schedules::Column::ConnectionId.eq(id.parse::<uuid::Uuid>().unwrap()))
            .filter(schedules::Column::JobType.eq("full_scan"))
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(s.cron_local, "30 6 * * *");
        let now = chrono::Utc::now();
        let want = next_after(
            "30 6 * * *",
            &s.timezone,
            end_of_local_day(&s.timezone, now).unwrap(),
        );
        let due = s.next_due_at.map(|d| d.with_timezone(&chrono::Utc));
        assert_eq!(due, want);
        assert!(
            due.unwrap() - now > chrono::Duration::hours(1),
            "not today: {due:?}"
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn create_aws_without_outbound_role_is_503_and_writes_nothing() {
    serve_with(
        |c| c.aws_outbound_role_arn = None,
        |req, ctx| async move {
            let mail = prepare(&ctx);
            let t = sign_in(&req, &mail, "owner@example.com").await;
            let org = slug(&create_org(&req, &t, "Acme").await);
            let res = req
                .post(&format!("/v1/orgs/{org}/connections"))
                .add_header("X-CSRF-Token", &t)
                .json(&json!({ "provider": "aws", "display_name": "Production" }))
                .await;
            assert_eq!(res.status_code(), 503, "{}", res.text());
            assert_eq!(res.json::<Value>()["code"], "connector_unavailable");
            assert_eq!(connections::Entity::find().count(&ctx.db).await.unwrap(), 0);
        },
    )
    .await;
}
