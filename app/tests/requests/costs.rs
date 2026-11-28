use opsagent_brain::models::_entities::findings;
use sea_orm::{entity::prelude::*, DbBackend, Statement};
use serde_json::{json, Value};
use serial_test::serial;

use super::support::*;
use crate::workers::full_scan::{noisy, scan};

/// The connection's newest 60 days (the fixture's), as the nightly scan stores them.
const FIRST_DAY: &str = "2026-08-02";
const NEWEST_DAY: &str = "2026-09-30";

async fn exec(ctx: &TestApp, sql: &str, conn: Uuid) {
    let st = Statement::from_sql_and_values(DbBackend::Postgres, sql, [conn.into()]);
    ctx.db.execute_raw(st).await.unwrap();
}

/// A check 01 cost-spike finding named `identity`, in `status`.
async fn spike(ctx: &TestApp, conn: Uuid, identity: &str, status: &str) {
    let q = "INSERT INTO findings (id, organisation_id, connection_id, check_id, resource_identity, \
             variant, severity, status, title) SELECT gen_random_uuid(), organisation_id, id, '01', \
             $2, 'cost_anomaly', 'low', $3, 't' FROM connections WHERE id = $1";
    let st = Statement::from_sql_and_values(
        DbBackend::Postgres,
        q,
        [conn.into(), identity.into(), status.into()],
    );
    ctx.db.execute_raw(st).await.unwrap();
}

async fn finding_id(ctx: &TestApp, identity: &str) -> String {
    let f = findings::Entity::find()
        .filter(findings::Column::ResourceIdentity.eq(identity))
        .one(&ctx.db)
        .await
        .unwrap();
    f.unwrap().id.to_string()
}

#[tokio::test]
#[serial]
async fn series_is_the_newest_60_days_and_flags_the_spike() {
    serve(|req, ctx| async move {
        let (_, org, conn) = connected(&req, &ctx, "o@example.com", "noisy").await;
        scan(&ctx, conn, 0, &noisy()).await;
        // Older than 60 days before the newest stored day, and spikes outside the window or
        // without a day: not shown. A resolved spike is still flagged.
        let old = "INSERT INTO cost_daily (organisation_id, connection_id, day, service, amount_usd) \
                   SELECT organisation_id, id, '2026-07-15', 'ec2', 9 FROM connections WHERE id = $1";
        exec(&ctx, old, conn).await;
        spike(&ctx, conn, "cost:2026-07-15", "open").await;
        spike(&ctx, conn, "cost:soon", "open").await;
        spike(&ctx, conn, "cost:2026-09-20", "resolved").await;

        let res = req.get(&format!("/v1/orgs/{org}/connections/{conn}/costs")).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        let body: Value = res.json();
        assert_eq!(body["newest_day"], NEWEST_DAY);
        let days = body["days"].as_array().unwrap();
        assert_eq!(days.len(), 60);
        // Amounts are strings with four decimals; days run oldest first.
        assert_eq!(days[0], json!({"day": FIRST_DAY, "service": "ec2", "amount_usd": "80.0000"}));
        assert_eq!(days[59], json!({"day": NEWEST_DAY, "service": "ec2", "amount_usd": "100.0000"}));
        assert_eq!(days[57]["amount_usd"], "500.0000");
        let spiked = finding_id(&ctx, "cost:2026-09-28").await;
        let resolved = finding_id(&ctx, "cost:2026-09-20").await;
        assert_eq!(
            body["flagged"],
            json!([
                {"day": "2026-09-20", "finding_id": resolved, "status": "resolved"},
                {"day": "2026-09-28", "finding_id": spiked, "status": "open"},
            ])
        );

        // Any member reads it.
        let mail = prepare(&ctx);
        let mut req = req;
        as_member(&mut req, &ctx, &mail, &org, "member@example.com").await;
        let url = format!("/v1/orgs/{org}/connections/{conn}/costs");
        assert_eq!(req.get(&url).await.status_code(), 200);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn a_credit_comes_back_negative() {
    serve(|req, ctx| async move {
        let (_, org, conn) = connected(&req, &ctx, "o@example.com", "noisy").await;
        let credit = "INSERT INTO cost_daily (organisation_id, connection_id, day, service, amount_usd) \
                      SELECT organisation_id, id, '2026-09-30', 'Credit', -5 FROM connections WHERE id = $1";
        exec(&ctx, credit, conn).await;
        let res = req.get(&format!("/v1/orgs/{org}/connections/{conn}/costs")).await;
        let body: Value = res.json();
        assert_eq!(
            body["days"],
            json!([{"day": NEWEST_DAY, "service": "Credit", "amount_usd": "-5.0000"}])
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn no_spend_stored_is_an_empty_series() {
    serve(|req, ctx| async move {
        let (_, org, conn) = connected(&req, &ctx, "o@example.com", "noisy").await;
        let res = req
            .get(&format!("/v1/orgs/{org}/connections/{conn}/costs"))
            .await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        assert_eq!(
            res.json::<Value>(),
            json!({"newest_day": null, "days": [], "flagged": []})
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn cross_org_costs_are_the_same_404_as_unknown() {
    serve(|mut req, ctx| async move {
        let mail = prepare(&ctx);
        let (_, _, idb) = fake_connection(&req, &mail, "b@example.com", "Org B", "noisy").await;
        let idb: Uuid = idb.parse().unwrap();
        scan(&ctx, idb, 0, &noisy()).await;
        req.clear_cookies();
        let ta = sign_in(&req, &mail, "a@example.com").await;
        let oa = slug(&create_org(&req, &ta, "Org A").await);
        let res = req
            .get(&format!("/v1/orgs/{oa}/connections/{idb}/costs"))
            .await;
        let unknown = req
            .get(&format!(
                "/v1/orgs/{oa}/connections/{}/costs",
                Uuid::new_v4()
            ))
            .await;
        let malformed = req
            .get(&format!("/v1/orgs/{oa}/connections/nope/costs"))
            .await;
        for r in [&res, &unknown, &malformed] {
            assert_eq!(r.status_code(), 404, "{}", r.text());
        }
        let (mut x, mut y) = (res.json::<Value>(), unknown.json::<Value>());
        x["instance"] = Value::Null;
        y["instance"] = Value::Null;
        assert_eq!(x, y);
    })
    .await;
}
