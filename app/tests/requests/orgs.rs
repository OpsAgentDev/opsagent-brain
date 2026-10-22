use loco_rs::prelude::*;
use opsagent_brain::models::_entities::{audit_events, connections, organisations, schedules};
use serde_json::{json, Value};
use serial_test::serial;

use super::support::*;

#[tokio::test]
#[serial]
async fn create_org_requires_csrf_then_stores_wrapped_dek() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        let token = sign_in(&req, &mail, "owner@example.com").await;

        let res = req.post("/v1/orgs").json(&json!({"name": "Acme"})).await;
        assert_eq!(res.status_code(), 403);
        assert_eq!(res.json::<Value>()["code"], "csrf");

        let org = create_org(&req, &token, "Acme").await;
        assert_eq!(org["role"], "owner");
        assert_eq!(org["timezone"], "UTC");
        let row = organisations::Entity::find()
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        assert!(row.wrapped_dek.is_some_and(|d| !d.is_empty()));
        assert_eq!(row.kek_version, Some(1));
        let audits = audit_events::Entity::find()
            .filter(audit_events::Column::Action.eq("org.create"))
            .count(&ctx.db)
            .await
            .unwrap();
        assert_eq!(audits, 1);

        let res = req
            .patch(&format!("/v1/orgs/{}", org["slug"].as_str().unwrap()))
            .add_header("X-CSRF-Token", &token)
            .json(&json!({"timezone": "Not/AZone"}))
            .await;
        assert_eq!(res.status_code(), 422);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn non_member_gets_same_404_as_unknown_org() {
    serve(|mut req, ctx| async move {
        let mail = prepare(&ctx);
        let ta = sign_in(&req, &mail, "a@example.com").await;
        create_org(&req, &ta, "Org A").await;
        req.clear_cookies();
        let tb = sign_in(&req, &mail, "b@example.com").await;
        let b = create_org(&req, &tb, "Org B").await;
        req.clear_cookies();
        sign_in(&req, &mail, "a@example.com").await;

        let slug = b["slug"].as_str().unwrap();
        let res = req.get(&format!("/v1/orgs/{slug}")).await;
        let unknown = req.get("/v1/orgs/does-not-exist").await;
        assert_eq!(res.status_code(), 404);
        assert_eq!(unknown.status_code(), 404);
        let (mut x, mut y) = (res.json::<Value>(), unknown.json::<Value>());
        x["instance"] = Value::Null;
        y["instance"] = Value::Null;
        assert_eq!(x, y);
        assert_eq!(req.get("/v1/orgs").await.json::<Vec<Value>>().len(), 1);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn removing_last_owner_is_409() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        let t = sign_in(&req, &mail, "o@example.com").await;
        let org = create_org(&req, &t, "Solo").await;
        let slug = org["slug"].as_str().unwrap();
        let members = req
            .get(&format!("/v1/orgs/{slug}/members"))
            .await
            .json::<Vec<Value>>();
        let id = members[0]["id"].as_str().unwrap();
        let res = req
            .delete(&format!("/v1/orgs/{slug}/members/{id}"))
            .add_header("X-CSRF-Token", &t)
            .await;
        assert_eq!(res.status_code(), 409);
        assert_eq!(res.json::<Value>()["code"], "last_owner");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn invites_owner_only_and_bound_to_email() {
    serve(|mut req, ctx| async move {
        let mail = prepare(&ctx);
        let t = sign_in(&req, &mail, "owner@example.com").await;
        let org = create_org(&req, &t, "Team").await;
        let slug = org["slug"].as_str().unwrap().to_string();
        let invite = |role: &str| json!({"email": "mate@example.com", "role": role});

        let res = req
            .post(&format!("/v1/orgs/{slug}/invites"))
            .add_header("X-CSRF-Token", &t)
            .json(&invite("member"))
            .await;
        assert_eq!(res.status_code(), 201, "{}", res.text());
        let accept = format!("/v1/invites/{}/accept", token_of(&last_link(&mail)));

        // Wrong user is refused.
        req.clear_cookies();
        let tw = sign_in(&req, &mail, "wrong@example.com").await;
        let res = req.post(&accept).add_header("X-CSRF-Token", &tw).await;
        assert_eq!(res.status_code(), 403);
        assert_eq!(res.json::<Value>()["code"], "invite_email_mismatch");

        // Right user joins as member, and then cannot invite.
        req.clear_cookies();
        let tm = sign_in(&req, &mail, "mate@example.com").await;
        let res = req.post(&accept).add_header("X-CSRF-Token", &tm).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        let res = req
            .post(&format!("/v1/orgs/{slug}/invites"))
            .add_header("X-CSRF-Token", &tm)
            .json(&invite("member"))
            .await;
        assert_eq!(res.status_code(), 403);
        assert_eq!(res.json::<Value>()["code"], "forbidden");

        // Re-invite, then remove the member: the pending invite is cancelled (accept -> 410).
        req.clear_cookies();
        let to = sign_in(&req, &mail, "owner@example.com").await;
        let res = req
            .post(&format!("/v1/orgs/{slug}/invites"))
            .add_header("X-CSRF-Token", &to)
            .json(&invite("member"))
            .await;
        assert_eq!(res.status_code(), 201);
        let accept2 = format!("/v1/invites/{}/accept", token_of(&last_link(&mail)));
        let members = req
            .get(&format!("/v1/orgs/{slug}/members"))
            .await
            .json::<Vec<Value>>();
        let mate = members
            .iter()
            .find(|m| m["email"] == "mate@example.com")
            .unwrap();
        let res = req
            .delete(&format!(
                "/v1/orgs/{slug}/members/{}",
                mate["id"].as_str().unwrap()
            ))
            .add_header("X-CSRF-Token", &to)
            .await;
        assert_eq!(res.status_code(), 204);
        req.clear_cookies();
        let tm = sign_in(&req, &mail, "mate@example.com").await;
        let res = req.post(&accept2).add_header("X-CSRF-Token", &tm).await;
        assert_eq!(res.status_code(), 410);

        // Token is single use.
        let res = req.post(&accept).add_header("X-CSRF-Token", &tm).await;
        assert_eq!(res.status_code(), 410);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn deleting_an_org_disconnects_its_connections_and_stops_scheduling() {
    use opsagent_brain::{
        models::{_entities::runs, ledger_storage::PgStorage},
        tasks::scheduler_tick::tick,
        workers::verify::{VerifyArgs, VerifyWorker},
    };
    use opsagent_core::run::RunKey;
    use opsagent_ledger::Storage;
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        let (t, org, id) = fake_connection(&req, &mail, "o@example.com", "Org", "clean").await;
        assert_eq!(verify(&req, &t, &org, &id, "").await.status_code(), 202);
        let conn_id: uuid::Uuid = id.parse().unwrap();
        let res = req
            .delete(&format!("/v1/orgs/{org}"))
            .add_header("X-CSRF-Token", &t)
            .await;
        assert_eq!(res.status_code(), 204);
        let c = connections::Entity::find_by_id(conn_id)
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (c.status.as_str(), c.status_reason.as_deref()),
            ("disconnected", Some("organisation_deleted"))
        );
        let enabled = |ctx: AppContext| async move {
            schedules::Entity::find()
                .filter(schedules::Column::ConnectionId.eq(conn_id))
                .filter(schedules::Column::Enabled.eq(true))
                .count(&ctx.db)
                .await
                .unwrap()
        };
        assert_eq!(enabled(ctx.clone()).await, 0);

        // Defence in depth: a schedule re-enabled by hand is still not run for a deleted org.
        let now = chrono::Utc::now();
        schedules::Entity::update_many()
            .col_expr(schedules::Column::Enabled, true.into())
            .col_expr(
                schedules::Column::NextDueAt,
                (now - chrono::Duration::minutes(1)).into(),
            )
            .filter(schedules::Column::ConnectionId.eq(conn_id))
            .exec(&ctx.db)
            .await
            .unwrap();
        runs::Entity::delete_many().exec(&ctx.db).await.unwrap();
        assert_eq!(tick(&ctx, now).await.unwrap().unwrap(), Default::default());
        assert_eq!(runs::Entity::find().count(&ctx.db).await.unwrap(), 0);

        // And a run that slipped through is skipped by the worker.
        let run = PgStorage::new(ctx.db.clone())
            .create_run(RunKey {
                organisation_id: Some(c.organisation_id),
                connection_id: Some(conn_id),
                job_type: "verify".into(),
                scheduled_at: now,
            })
            .await
            .unwrap()
            .run;
        VerifyWorker::build(&ctx)
            .perform(VerifyArgs { run_id: run.id })
            .await
            .unwrap();
        let r = runs::Entity::find_by_id(run.id)
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (r.status.as_str(), r.partial_reason.as_deref()),
            ("skipped", Some("organisation_deleted"))
        );
    })
    .await;
}
