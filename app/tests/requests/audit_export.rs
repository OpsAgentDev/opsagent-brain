//! `GET /orgs/{org}/audit` and `POST /orgs/{org}/export`: owners only, one organisation only.
use opsagent_brain::{
    adapters::db::Pg,
    models::_entities::{audit_events, organisations},
};
use opsagent_core::audit::{AuditEntry, AuditLog};
use sea_orm::entity::prelude::*;
use serde_json::{json, Value};
use serial_test::serial;
use uuid::Uuid;

use super::support::*;

async fn org_id(ctx: &TestApp, slug: &str) -> Uuid {
    let row = organisations::Entity::find()
        .filter(organisations::Column::Slug.eq(slug))
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap();
    row.id
}

async fn record(ctx: &TestApp, org: Uuid, action: &str, meta: Value) {
    let e = AuditEntry::system(org, action, ("connection", "c".into()), "success");
    let pg = Pg::new(&ctx.db);
    pg.record(e.with_meta(meta)).await.unwrap();
}

/// Owner `a@example.com` of "Org A" is signed in; "Org B" belongs to someone else.
async fn two_orgs(
    req: &mut axum_test::TestServer,
    ctx: &TestApp,
    mail: &opsagent_brain::mailers::CaptureMailer,
) -> (String, String, String) {
    let tb = sign_in(req, mail, "b@example.com").await;
    let b = slug(&create_org(req, &tb, "Org B").await);
    create_connection(req, &tb, &b, "aws", "Theirs Prod").await;
    record(ctx, org_id(ctx, &b).await, "b.only", json!({})).await;
    req.clear_cookies();
    let ta = sign_in(req, mail, "a@example.com").await;
    let a = slug(&create_org(req, &ta, "Org A").await);
    (ta, a, b)
}

#[tokio::test]
#[serial]
async fn audit_lists_own_entries_newest_first_in_pages_for_owners_only() {
    serve(|mut req, ctx| async move {
        let mail = prepare(&ctx);
        let (_, a, b) = two_orgs(&mut req, &ctx, &mail).await;
        let id = org_id(&ctx, &a).await;
        let secret = json!({ "refresh_token": "s3cr3t-value-1", "run_id": "r1" });
        for (action, meta) in [
            ("x.first", secret),
            ("x.second", json!({})),
            ("x.third", json!({})),
        ] {
            record(&ctx, id, action, meta).await;
        }

        let res = req.get(&format!("/v1/orgs/{a}/audit")).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        let page: Value = res.json();
        let items = page["items"].as_array().unwrap();
        let actions: Vec<_> = items
            .iter()
            .map(|i| i["action"].as_str().unwrap())
            .collect();
        assert_eq!(actions[..3], ["x.third", "x.second", "x.first"]);
        assert!(!actions.contains(&"b.only"), "{actions:?}");
        assert!(page["next_cursor"].is_null());
        assert_eq!(items[0]["actor"], "OpsAgent");
        assert_eq!(items[0]["actor_type"], "system");
        assert_eq!(items[0]["target_type"], "connection");
        assert_eq!(items[2]["metadata"], json!({ "run_id": "r1" }));
        assert!(!res.text().contains("s3cr3t-value-1"));
        let created = items.iter().find(|i| i["action"] == "org.create").unwrap();
        assert_eq!(created["actor_type"], "member");
        assert!(created["actor"].as_str().unwrap().contains("a@example.com"));

        // Two per page, then the next page from the cursor.
        let first: Value = req.get(&format!("/v1/orgs/{a}/audit?limit=2")).await.json();
        assert_eq!(first["items"].as_array().unwrap().len(), 2);
        assert_eq!(first["items"][1]["action"], "x.second");
        let cursor = first["next_cursor"].as_str().unwrap();
        let path = format!("/v1/orgs/{a}/audit?limit=2&cursor={cursor}");
        let second: Value = req.get(&path).await.json();
        assert_eq!(second["items"][0]["action"], "x.first");
        let bad = req.get(&format!("/v1/orgs/{a}/audit?cursor=nope")).await;
        assert_eq!(bad.status_code(), 422);

        // Another organisation's log is the same 404 as an unknown organisation.
        assert_eq!(
            req.get(&format!("/v1/orgs/{b}/audit")).await.status_code(),
            404
        );

        as_member(&mut req, &ctx, &mail, &a, "mate@example.com").await;
        let res = req.get(&format!("/v1/orgs/{a}/audit")).await;
        assert_eq!(res.status_code(), 403);
        assert_eq!(res.json::<Value>()["code"], "forbidden");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn export_downloads_own_data_once_an_hour_for_owners_only() {
    serve(|mut req, ctx| async move {
        let mail = prepare(&ctx);
        let (t, a, _) = two_orgs(&mut req, &ctx, &mail).await;
        create_connection(&req, &t, &a, "aws", "Mine Prod").await;
        let path = format!("/v1/orgs/{a}/export");

        let res = req.post(&path).await;
        assert_eq!(res.status_code(), 403);
        assert_eq!(res.json::<Value>()["code"], "csrf");

        let res = req.post(&path).add_header("X-CSRF-Token", &t).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        let disposition = res.header("content-disposition");
        let want = format!("attachment; filename=\"opsagent-export-{a}.json\"");
        assert_eq!(disposition.to_str().unwrap(), want);
        let (text, doc) = (res.text(), res.json::<Value>());
        let mut keys: Vec<_> = doc.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "audit_log",
                "connections",
                "deliveries",
                "delivery_settings",
                "exported_at",
                "findings",
                "members",
                "organisation",
                "recipients",
            ]
        );
        assert_eq!(doc["organisation"]["slug"], a.as_str());
        assert_eq!(doc["members"][0]["email"], "a@example.com");
        assert_eq!(doc["connections"][0]["display_name"], "Mine Prod");
        assert!(doc["connections"][0].get("external_id").is_none());
        for absent in [
            "Org B",
            "Theirs Prod",
            "b@example.com",
            "b.only",
            "ciphertext",
            "nonce",
            "wrapped_dek",
            "kek_version",
            "external_id",
            "customer_id",
            "subscription_id",
        ] {
            assert!(!text.contains(absent), "{absent}");
        }

        let again = req.post(&path).add_header("X-CSRF-Token", &t).await;
        assert_eq!(again.status_code(), 429);
        assert_eq!(again.json::<Value>()["code"], "rate_limited");
        assert_eq!(again.header("retry-after"), "3600");
        let audited = audit_events::Entity::find()
            .filter(audit_events::Column::Action.eq("org.exported"))
            .filter(audit_events::Column::OrganisationId.eq(org_id(&ctx, &a).await))
            .count(&ctx.db)
            .await
            .unwrap();
        assert_eq!(audited, 1);

        let tm = as_member(&mut req, &ctx, &mail, &a, "mate@example.com").await;
        let res = req.post(&path).add_header("X-CSRF-Token", &tm).await;
        assert_eq!(res.status_code(), 403);
        assert_eq!(res.json::<Value>()["code"], "forbidden");
    })
    .await;
}
