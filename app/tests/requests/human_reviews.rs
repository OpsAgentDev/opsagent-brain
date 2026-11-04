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
use wiremock::{
    matchers::{body_string_contains, method, path},
    Mock, MockServer, ResponseTemplate,
};

use super::{
    billing::{deliver, deliver_any, event, stripe_on},
    support::*,
};
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
        let audits = audit_events::Entity::find()
            .filter(audit_events::Column::Action.eq("human_review.request"))
            .all(&ctx.db)
            .await
            .unwrap();
        assert!(audits.is_empty(), "{audits:?}");
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
        let mail = prepare(&ctx);
        let res = post(&req, &t, &org, body).await;
        assert_eq!(res.status_code(), 429);
        assert_eq!(res.json::<Value>()["code"], "rate_limited");
        assert_eq!(rows(&ctx, &org).await.len(), 5);
        assert!(mail.sent().is_empty(), "{:?}", mail.sent());
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

/// Mounts Stripe's customer create (`cus_1`) and a Checkout session for `kind` at `cents`.
async fn mount_checkout(api: &MockServer, kind: &str, cents: u32) {
    Mock::given(method("POST"))
        .and(path("/v1/customers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": "cus_1" })))
        .mount(api)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/checkout/sessions"))
        .and(body_string_contains("mode=payment"))
        .and(body_string_contains("customer=cus_1"))
        .and(body_string_contains(format!(
            "price_data%5D%5Bunit_amount%5D={cents}&"
        )))
        .and(body_string_contains("price_data%5D%5Bcurrency%5D=usd"))
        .and(body_string_contains(format!(
            "product_data%5D%5Bname%5D=OpsAgent+human+review%3A+{kind}"
        )))
        .and(body_string_contains("tax_code%5D=txcd_10103001"))
        .and(body_string_contains("metadata%5Bpurpose%5D=human_review"))
        .and(body_string_contains("metadata%5Breview_request_id%5D="))
        .and(body_string_contains("settings%2Fhuman-review%3Fpaid%3D1"))
        .and(body_string_contains(
            "settings%2Fhuman-review%3Fcanceled%3D1",
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "url": "https://checkout.test/r" })),
        )
        .expect(1)
        .mount(api)
        .await;
}

#[tokio::test]
#[serial]
async fn with_stripe_a_request_returns_checkout_and_mails_nothing() {
    let api = MockServer::start().await;
    serve_with(stripe_on(api.uri()), |mut req, ctx| async move {
        let (t, org, conn, fid) = fixture(&mut req, &ctx, "o@example.com").await;
        mount_checkout(&api, "finding", 9900).await;
        let mail = prepare(&ctx);
        let res = post(&req, &t, &org, json!({"kind":"finding","finding_id":fid})).await;
        assert_eq!(res.status_code(), 201, "{}", res.text());
        let body = res.json::<Value>();
        assert_eq!(body["checkout_url"], "https://checkout.test/r");
        let r = rows(&ctx, &org).await;
        assert_eq!((r[0].payment.as_str(), r[0].paid_at), ("pending", None));
        assert_eq!(body["id"], r[0].id.to_string());
        let sent = api.received_requests().await.unwrap();
        let session = sent
            .iter()
            .find(|q| q.url.path() == "/v1/checkout/sessions")
            .unwrap();
        let idem = session
            .headers
            .get("Idempotency-Key")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(idem, format!("human_review:{}", r[0].id));
        let form = String::from_utf8_lossy(&session.body);
        assert!(
            form.contains(&format!("metadata%5Breview_request_id%5D={}", r[0].id)),
            "{form}"
        );
        assert!(mail.sent().is_empty(), "{:?}", mail.sent());
        api.verify().await;

        api.reset().await;
        mount_checkout(&api, "account", 49900).await;
        let res = post(
            &req,
            &t,
            &org,
            json!({"kind":"account","connection_id":conn}),
        )
        .await;
        assert_eq!(res.status_code(), 201, "{}", res.text());
        assert_eq!(
            res.json::<Value>()["checkout_url"],
            "https://checkout.test/r"
        );
        assert!(mail.sent().is_empty());
    })
    .await;
}

#[tokio::test]
#[serial]
async fn with_stripe_down_a_request_is_502_and_mails_nothing() {
    let api = MockServer::start().await;
    serve_with(stripe_on(api.uri()), |mut req, ctx| async move {
        let (t, org, _, fid) = fixture(&mut req, &ctx, "o@example.com").await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&api)
            .await;
        let mail = prepare(&ctx);
        let res = post(&req, &t, &org, json!({"kind":"finding","finding_id":fid})).await;
        assert_eq!(res.status_code(), 502, "{}", res.text());
        assert_eq!(res.json::<Value>()["code"], "billing_unavailable");
        assert_eq!(rows(&ctx, &org).await[0].payment, "pending");
        assert!(mail.sent().is_empty());
    })
    .await;
}

fn paid_event(id: &str, kind: &str, status: &str, org: Uuid, review: Uuid) -> Value {
    event(
        id,
        kind,
        10,
        json!({ "id": "cs_h", "object": "checkout.session", "mode": "payment",
            "payment_status": status, "client_reference_id": org.to_string(), "customer": "cus_1",
            "metadata": { "purpose": "human_review", "review_request_id": review.to_string() } }),
    )
}

#[tokio::test]
#[serial]
async fn webhook_marks_paid_once_then_mails() {
    let api = MockServer::start().await;
    serve_with(stripe_on(api.uri()), |mut req, ctx| async move {
        let (t, org, _, fid) = fixture(&mut req, &ctx, "o@example.com").await;
        mount_checkout(&api, "finding", 9900).await;
        let note = json!({"kind":"finding","finding_id":fid,"note":"please"});
        assert_eq!(post(&req, &t, &org, note).await.status_code(), 201);
        let r = rows(&ctx, &org).await.remove(0);
        let (o, id) = (r.organisation_id, r.id);
        let mail = prepare(&ctx);
        let done = "checkout.session.completed";
        // Unpaid (a delayed method) does nothing.
        deliver(&req, &paid_event("evt_h0", done, "unpaid", o, id)).await;
        assert_eq!(rows(&ctx, &org).await[0].payment, "pending");
        assert!(mail.sent().is_empty());
        // Another org's id never marks it, even while it is pending.
        deliver(&req, &paid_event("evt_h3", done, "paid", Uuid::new_v4(), id)).await;
        assert_eq!(rows(&ctx, &org).await[0].payment, "pending");
        assert!(mail.sent().is_empty());
        deliver(&req, &paid_event("evt_h1", done, "paid", o, id)).await;
        let row = rows(&ctx, &org).await.remove(0);
        assert_eq!(row.payment, "paid");
        assert!(row.paid_at.is_some());
        let sent = mail.sent();
        assert_eq!(sent.len(), 2, "{sent:?}");
        let founder = sent.iter().find(|m| m.to == "info@opsagent.dev").unwrap();
        assert_eq!(founder.subject, "Human review paid: finding · o@example.com");
        assert_eq!(founder.reply_to.as_deref(), Some("o@example.com"));
        let check = findings::Entity::find_by_id(fid).one(&ctx.db).await.unwrap().unwrap().check_id;
        assert!(
            founder.text.contains(&format!("finding {check} ({fid})")),
            "{}",
            founder.text
        );
        assert!(founder.text.contains("please"));
        let owner = sent.iter().find(|m| m.to == "o@example.com").unwrap();
        assert!(owner.text.contains(
            "Payment received. Harun will reply within 1 business day. Nothing is changed in your account."
        ), "{}", owner.text);
        // A replay and a second event for the same request send nothing more.
        deliver(&req, &paid_event("evt_h1", done, "paid", o, id)).await;
        let late = "checkout.session.async_payment_succeeded";
        deliver(&req, &paid_event("evt_h2", late, "paid", o, id)).await;
        assert_eq!(mail.sent().len(), 2);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn webhook_with_a_failing_mailer_is_retried_not_lost() {
    let api = MockServer::start().await;
    serve_with(stripe_on(api.uri()), |mut req, ctx| async move {
        let (t, org, _, fid) = fixture(&mut req, &ctx, "o@example.com").await;
        mount_checkout(&api, "finding", 9900).await;
        assert_eq!(
            post(&req, &t, &org, json!({"kind":"finding","finding_id":fid}))
                .await
                .status_code(),
            201
        );
        let r = rows(&ctx, &org).await.remove(0);
        let ev = paid_event(
            "evt_m1",
            "checkout.session.completed",
            "paid",
            r.organisation_id,
            r.id,
        );
        let failing: Arc<dyn Mailer> = Arc::new(Failing);
        ctx.set_mailer(failing);
        // Mail down: Stripe sees a failure and the event is not recorded as handled.
        assert_eq!(deliver_any(&req, &ev).await.status_code(), 500);
        assert_eq!(rows(&ctx, &org).await[0].payment, "pending");
        // The redelivery of the same event succeeds and sends both mails.
        let mail = prepare(&ctx);
        deliver(&req, &ev).await;
        assert_eq!(rows(&ctx, &org).await[0].payment, "paid");
        assert_eq!(mail.sent().len(), 2);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn webhook_async_payment_marks_paid() {
    let api = MockServer::start().await;
    serve_with(stripe_on(api.uri()), |mut req, ctx| async move {
        let (t, org, _, fid) = fixture(&mut req, &ctx, "o@example.com").await;
        mount_checkout(&api, "finding", 9900).await;
        assert_eq!(
            post(&req, &t, &org, json!({"kind":"finding","finding_id":fid}))
                .await
                .status_code(),
            201
        );
        let r = rows(&ctx, &org).await.remove(0);
        let mail = prepare(&ctx);
        let late = "checkout.session.async_payment_succeeded";
        deliver(
            &req,
            &paid_event("evt_a1", late, "paid", r.organisation_id, r.id),
        )
        .await;
        assert_eq!(rows(&ctx, &org).await[0].payment, "paid");
        assert_eq!(mail.sent().len(), 2);
        let list = req
            .get(&format!("/v1/orgs/{org}/human-reviews"))
            .await
            .json::<Value>();
        assert_eq!(list["requests"][0]["payment"], "paid");
        assert!(list["requests"][0]["paid_at"].is_string());
    })
    .await;
}

#[tokio::test]
#[serial]
async fn without_stripe_requests_are_invoiced() {
    serve(|mut req, ctx| async move {
        let (t, org, _, fid) = fixture(&mut req, &ctx, "o@example.com").await;
        let res = post(&req, &t, &org, json!({"kind":"finding","finding_id":fid})).await;
        assert_eq!(res.status_code(), 201);
        assert!(res.json::<Value>()["checkout_url"].is_null());
        assert_eq!(rows(&ctx, &org).await[0].payment, "invoice");
        let list = req
            .get(&format!("/v1/orgs/{org}/human-reviews"))
            .await
            .json::<Value>();
        assert_eq!(list["requests"][0]["payment"], "invoice");
        assert!(list["requests"][0]["paid_at"].is_null());
    })
    .await;
}

#[tokio::test]
#[serial]
async fn read_only_org_can_still_request() {
    use super::billing_gate::{enforced, owner_org, set_billing};
    serve_with(enforced, |mut req, ctx| async move {
        let (t, org, id) = owner_org(&req, &prepare(&ctx)).await;
        set_billing(&ctx, id, "active", "team", 0).await;
        let c = create_connection(&req, &t, &org, "fake", "noisy").await;
        let conn: Uuid = c["id"].as_str().unwrap().parse().unwrap();
        let mut a: connections::ActiveModel = connections::Entity::find_by_id(conn)
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap()
            .into();
        a.status = Set("connected".into());
        a.external_account_id = Set(Some("noisy-owner".into()));
        a.update(&ctx.db).await.unwrap();
        scan(&ctx, conn, 0, &noisy()).await;
        ctx.drain_jobs().await;
        let f = findings::Entity::find()
            .filter(findings::Column::ConnectionId.eq(conn))
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        set_billing(&ctx, id, "canceled", "team", 0).await;
        // Writes are refused (402), the human review is exempt.
        let res = req
            .patch(&format!("/v1/orgs/{org}"))
            .add_header("X-CSRF-Token", &t)
            .json(&json!({ "name": "Acme 2" }))
            .await;
        assert_eq!(res.status_code(), 402, "{}", res.text());
        let res = post(&req, &t, &org, json!({"kind":"finding","finding_id":f.id})).await;
        assert_eq!(res.status_code(), 201, "{}", res.text());
        assert_eq!(rows(&ctx, &org).await.len(), 1);
        let _ = &mut req;
    })
    .await;
}
