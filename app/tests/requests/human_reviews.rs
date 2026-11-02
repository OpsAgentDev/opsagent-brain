use std::sync::Arc;

use async_trait::async_trait;
use opsagent_brain::mailers::{Mail, Mailer};
use opsagent_brain::models::_entities::{
    audit_events, connections, findings, human_review_requests,
};
use sea_orm::{entity::prelude::*, ActiveModelTrait, Set};
use serde_json::{json, Value};
use serial_test::serial;
use uuid::Uuid;

use super::support::*;
use crate::workers::full_scan::{noisy, scan};

struct Failing;

#[async_trait]
impl Mailer for Failing {
    async fn send(&self, _: Mail) -> Result<(), String> {
        Err("down".into())
    }
}

/// Owner, org, a connected `noisy` connection scanned once; returns (csrf, org, conn, finding).
async fn fixture(
    req: &mut axum_test::TestServer,
    ctx: &TestApp,
    email: &str,
) -> (String, String, Uuid, Uuid) {
    req.clear_cookies();
    let (t, org, conn) = connected(req, ctx, email, "noisy").await;
    scan(ctx, conn, 0, &noisy()).await;
    ctx.drain_jobs().await; // the first-scan alert mail
    let f = findings::Entity::find()
        .filter(findings::Column::ConnectionId.eq(conn))
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap();
    (t, org, conn, f.id)
}

async fn post(
    req: &axum_test::TestServer,
    t: &str,
    org: &str,
    body: Value,
) -> axum_test::TestResponse {
    req.post(&format!("/v1/orgs/{org}/human-reviews"))
        .add_header("X-CSRF-Token", t)
        .json(&body)
        .await
}

async fn rows(ctx: &TestApp, org: &str) -> Vec<human_review_requests::Model> {
    use opsagent_brain::models::_entities::organisations;
    let o = organisations::Entity::find()
        .filter(organisations::Column::Slug.eq(org))
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap();
    human_review_requests::Entity::find()
        .filter(human_review_requests::Column::OrganisationId.eq(o.id))
        .all(&ctx.db)
        .await
        .unwrap()
}

#[tokio::test]
#[serial]
async fn owner_requests_a_finding_review() {
    serve(|mut req, ctx| async move {
        let (t, org, _, fid) = fixture(&mut req, &ctx, "o@example.com").await;
        let mail = prepare(&ctx);
        let res = post(&req, &t, &org, json!({"kind":"finding","finding_id":fid,"note":"please"})).await;
        assert_eq!(res.status_code(), 201, "{}", res.text());
        let id = res.json::<Value>()["id"].as_str().unwrap().to_owned();
        let r = rows(&ctx, &org).await;
        assert_eq!(r.len(), 1);
        let title = findings::Entity::find_by_id(fid).one(&ctx.db).await.unwrap().unwrap().title;
        assert_eq!((r[0].price_cents, r[0].target_label.as_str()), (9900, title.as_str()));
        let audit = audit_events::Entity::find()
            .filter(audit_events::Column::Action.eq("human_review.request"))
            .filter(audit_events::Column::TargetId.eq(fid.to_string()))
            .one(&ctx.db)
            .await
            .unwrap()
            .expect("audit row");
        assert_eq!(audit.target_type.as_deref(), Some("finding"));
        assert!(!id.is_empty());
        let sent = mail.sent();
        assert_eq!(sent.len(), 2, "{sent:?}");
        let founder = sent.iter().find(|m| m.to == "info@opsagent.dev").unwrap();
        assert_eq!(founder.subject, "Human review requested: finding · o@example.com");
        assert_eq!(founder.reply_to.as_deref(), Some("o@example.com"));
        let owner = sent.iter().find(|m| m.to == "o@example.com").unwrap();
        assert_eq!(owner.subject, "We got your human review request");
        assert!(owner.text.contains(
            "Harun will reply within 1 business day with a confirmation and invoice. Nothing is changed in your account."
        ));
    })
    .await;
}

#[tokio::test]
#[serial]
async fn account_review_needs_a_live_connection() {
    serve(|mut req, ctx| async move {
        let (t, org, conn, _) = fixture(&mut req, &ctx, "o@example.com").await;
        let res = post(
            &req,
            &t,
            &org,
            json!({"kind":"account","connection_id":conn}),
        )
        .await;
        assert_eq!(res.status_code(), 201, "{}", res.text());
        assert_eq!(rows(&ctx, &org).await[0].price_cents, 49900);
        let mut a: connections::ActiveModel = connections::Entity::find_by_id(conn)
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap()
            .into();
        a.status = Set("disconnected".into());
        a.update(&ctx.db).await.unwrap();
        let res = post(
            &req,
            &t,
            &org,
            json!({"kind":"account","connection_id":conn}),
        )
        .await;
        assert_eq!(res.status_code(), 422);
        assert_eq!(res.json::<Value>()["code"], "validation");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn wrong_target_or_long_note_is_422() {
    serve(|mut req, ctx| async move {
        let (t, org, _, fid) = fixture(&mut req, &ctx, "o@example.com").await;
        for body in [
            json!({"kind":"finding"}),
            json!({"kind":"account","finding_id":fid}),
            json!({"kind":"other","finding_id":fid}),
            json!({"kind":"finding","finding_id":fid,"note":"x".repeat(2001)}),
        ] {
            let res = post(&req, &t, &org, body).await;
            assert_eq!(res.status_code(), 422, "{}", res.text());
        }
        let ok = json!({"kind":"finding","finding_id":fid,"note":"x".repeat(2000)});
        assert_eq!(post(&req, &t, &org, ok).await.status_code(), 201);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn other_orgs_targets_are_404_without_side_effects() {
    serve(|mut req, ctx| async move {
        let (_, _, conn_a, fid_a) = fixture(&mut req, &ctx, "a@example.com").await;
        let (t, org, _, _) = fixture(&mut req, &ctx, "b@example.com").await;
        let mail = prepare(&ctx);
        for body in [
            json!({"kind":"finding","finding_id":fid_a}),
            json!({"kind":"account","connection_id":conn_a}),
            json!({"kind":"finding","finding_id":Uuid::new_v4()}),
        ] {
            assert_eq!(post(&req, &t, &org, body).await.status_code(), 404);
        }
        assert!(rows(&ctx, &org).await.is_empty());
        assert!(mail.sent().is_empty());
    })
    .await;
}

#[tokio::test]
#[serial]
async fn member_cannot_request() {
    serve(|mut req, ctx| async move {
        let (_, org, _, fid) = fixture(&mut req, &ctx, "o@example.com").await;
        let mail = prepare(&ctx);
        let t = as_member(&mut req, &ctx, &mail, &org, "m@example.com").await;
        let res = post(&req, &t, &org, json!({"kind":"finding","finding_id":fid})).await;
        assert_eq!(res.status_code(), 403);
        assert!(rows(&ctx, &org).await.is_empty());
    })
    .await;
}

#[tokio::test]
#[serial]
async fn sixth_request_in_a_day_is_429() {
    serve(|mut req, ctx| async move {
        let (t, org, _, fid) = fixture(&mut req, &ctx, "o@example.com").await;
        let body = json!({"kind":"finding","finding_id":fid});
        for _ in 0..5 {
            assert_eq!(post(&req, &t, &org, body.clone()).await.status_code(), 201);
        }
        let res = post(&req, &t, &org, body).await;
        assert_eq!(res.status_code(), 429);
        assert_eq!(rows(&ctx, &org).await.len(), 5);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn note_never_reaches_a_subject_or_header() {
    serve(|mut req, ctx| async move {
        let (t, org, _, fid) = fixture(&mut req, &ctx, "o@example.com").await;
        let mail = prepare(&ctx);
        let note = "<b>x</b>\nBcc: a@b";
        let res = post(
            &req,
            &t,
            &org,
            json!({"kind":"finding","finding_id":fid,"note":note}),
        )
        .await;
        assert_eq!(res.status_code(), 201);
        for m in mail.sent() {
            assert!(
                !m.subject.contains("<b>") && !m.subject.contains("Bcc"),
                "{}",
                m.subject
            );
            let headers = [Some(&m.subject), Some(&m.to), m.reply_to.as_ref()];
            for h in headers.into_iter().flatten() {
                assert!(!h.contains(['\n', '\r']), "{h:?}");
            }
        }
    })
    .await;
}

#[tokio::test]
#[serial]
async fn failing_mailer_does_not_fail_the_request() {
    serve(|mut req, ctx| async move {
        let (t, org, _, fid) = fixture(&mut req, &ctx, "o@example.com").await;
        let failing: Arc<dyn Mailer> = Arc::new(Failing);
        ctx.set_mailer(failing);
        let res = post(&req, &t, &org, json!({"kind":"finding","finding_id":fid})).await;
        assert_eq!(res.status_code(), 201);
        assert_eq!(rows(&ctx, &org).await.len(), 1);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn list_returns_offers_and_own_requests_newest_first() {
    serve(|mut req, ctx| async move {
        let _ = fixture(&mut req, &ctx, "a@example.com").await;
        let (t, org, conn, fid) = fixture(&mut req, &ctx, "b@example.com").await;
        post(&req, &t, &org, json!({"kind":"finding","finding_id":fid})).await;
        post(
            &req,
            &t,
            &org,
            json!({"kind":"account","connection_id":conn,"note":"n"}),
        )
        .await;
        let url = format!("/v1/orgs/{org}/human-reviews");
        let check = |v: Value| {
            let offers: Vec<_> = v["offers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|o| {
                    (
                        o["kind"].as_str().unwrap().to_owned(),
                        o["price_cents"].as_i64().unwrap(),
                    )
                })
                .collect();
            assert_eq!(
                offers,
                [("finding".to_owned(), 9900), ("account".to_owned(), 49900)]
            );
            let r = v["requests"].as_array().unwrap();
            assert_eq!(r.len(), 2);
            assert_eq!(
                (r[0]["kind"].as_str(), r[1]["kind"].as_str()),
                (Some("account"), Some("finding"))
            );
            assert_eq!(r[0]["requester_email"], "b@example.com");
            assert_eq!(r[0]["note"], "n");
        };
        check(req.get(&url).await.json());
        let mail = prepare(&ctx);
        as_member(&mut req, &ctx, &mail, &org, "m@example.com").await;
        let res = req.get(&url).await;
        assert_eq!(res.status_code(), 200);
        check(res.json());
    })
    .await;
}
