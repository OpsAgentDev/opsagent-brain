//! `StripeBilling` against a wiremock Stripe API, and the webhook signature check.
use chrono::{TimeZone, Utc};
use hmac::{Hmac, Mac};
use opsagent_brain::adapters::stripe::{
    verify_stripe_signature, SigError, StripeBilling, StripeSettings,
};
use opsagent_core::billing::{BillingError, BillingProvider, CheckoutRequest};
use serde_json::json;
use sha2::Sha256;
use uuid::Uuid;
use wiremock::{
    matchers::{header, method, path},
    Mock, MockServer, Request, ResponseTemplate,
};

const VERSION: &str = "2025-09-30.clover";

fn stripe(server: &MockServer, automatic_tax: bool) -> StripeBilling {
    StripeBilling::new(StripeSettings {
        api_base: server.uri(),
        secret_key: "sk_test_x".into(),
        api_version: VERSION.into(),
        automatic_tax,
    })
    .unwrap()
}

/// The decoded form body.
fn form(r: &Request) -> Vec<(String, String)> {
    let body = String::from_utf8_lossy(&r.body).replace('+', " ");
    let dec = |s: &str| urlencoding::decode(s).unwrap().into_owned();
    body.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| p.split_once('=').unwrap_or((p, "")))
        .map(|(k, v)| (dec(k), dec(v)))
        .collect()
}

/// Matches when the form has every pair in `want` and none of the keys in `absent`.
fn form_has(
    want: &'static [(&'static str, &'static str)],
    absent: &'static [&'static str],
) -> impl Fn(&Request) -> bool + Send + Sync {
    move |r| {
        let f = form(r);
        let has = |k: &str, v: &str| f.iter().any(|(a, b)| a == k && b == v);
        want.iter().all(|(k, v)| has(k, v)) && absent.iter().all(|k| f.iter().all(|(a, _)| a != k))
    }
}

fn checkout(trial: bool) -> CheckoutRequest {
    CheckoutRequest {
        organisation_id: Uuid::nil(),
        customer_id: "cus_1".into(),
        price_id: "price_team".into(),
        trial,
        success_url: "https://opsagent.dev/settings/billing?status=success".into(),
        cancel_url: "https://opsagent.dev/settings/billing?status=cancel".into(),
    }
}

fn session() -> ResponseTemplate {
    ResponseTemplate::new(200)
        .set_body_json(json!({"id": "cs_1", "url": "https://checkout.stripe.com/c/1"}))
}

#[tokio::test]
async fn stripe_checkout_sends_trial_params() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/checkout/sessions"))
        .and(header("authorization", "Bearer sk_test_x"))
        .and(header("stripe-version", VERSION))
        .and(header("idempotency-key", "checkout:1"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .and(form_has(
            &[
                ("mode", "subscription"),
                ("customer", "cus_1"),
                (
                    "client_reference_id",
                    "00000000-0000-0000-0000-000000000000",
                ),
                ("line_items[0][price]", "price_team"),
                ("line_items[0][quantity]", "1"),
                ("subscription_data[trial_period_days]", "14"),
                ("payment_method_collection", "always"),
                (
                    "subscription_data[trial_settings][end_behavior][missing_payment_method]",
                    "cancel",
                ),
                ("allow_promotion_codes", "true"),
                (
                    "success_url",
                    "https://opsagent.dev/settings/billing?status=success",
                ),
                (
                    "cancel_url",
                    "https://opsagent.dev/settings/billing?status=cancel",
                ),
            ],
            &["automatic_tax[enabled]"],
        ))
        .respond_with(session())
        .expect(1)
        .mount(&server)
        .await;
    let url = stripe(&server, false)
        .checkout_session(&checkout(true), "checkout:1")
        .await;
    assert_eq!(url.unwrap(), "https://checkout.stripe.com/c/1");
}

#[tokio::test]
async fn checkout_without_trial_and_with_tax() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/checkout/sessions"))
        .and(form_has(
            &[
                ("automatic_tax[enabled]", "true"),
                ("payment_method_collection", "always"),
            ],
            &["subscription_data[trial_period_days]"],
        ))
        .respond_with(session())
        .expect(1)
        .mount(&server)
        .await;
    let url = stripe(&server, true)
        .checkout_session(&checkout(false), "k")
        .await;
    assert_eq!(url.unwrap(), "https://checkout.stripe.com/c/1");
}

#[tokio::test]
async fn create_customer_and_portal_session() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/customers"))
        .and(header("idempotency-key", "customer:o"))
        .and(form_has(
            &[
                ("name", "Acme"),
                ("email", "o@example.com"),
                (
                    "metadata[organisation_id]",
                    "00000000-0000-0000-0000-000000000000",
                ),
            ],
            &[],
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "cus_9"})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/billing_portal/sessions"))
        .and(form_has(
            &[("customer", "cus_9"), ("return_url", "https://w/b")],
            &[],
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"url": "https://billing.stripe.com/p/1"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let s = stripe(&server, false);
    let id = s
        .create_customer(Uuid::nil(), "Acme", "o@example.com", "customer:o")
        .await;
    assert_eq!(id.unwrap(), "cus_9");
    let url = s.portal_session("cus_9", "https://w/b").await.unwrap();
    assert_eq!(url, "https://billing.stripe.com/p/1");
}

#[tokio::test]
async fn set_quantity_proration_flag() {
    for (prorate, behaviour) in [(true, "create_prorations"), (false, "none")] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/subscriptions/sub_1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"id": "sub_1", "items": {"data": [{"id": "si_1", "quantity": 1}]}}),
            ))
            .mount(&server)
            .await;
        let want: &'static [(&str, &str)] = if prorate {
            &[
                ("items[0][id]", "si_1"),
                ("items[0][quantity]", "3"),
                ("proration_behavior", "create_prorations"),
            ]
        } else {
            &[
                ("items[0][id]", "si_1"),
                ("items[0][quantity]", "3"),
                ("proration_behavior", "none"),
            ]
        };
        Mock::given(method("POST"))
            .and(path("/v1/subscriptions/sub_1"))
            .and(header("idempotency-key", "qty:1"))
            .and(header("stripe-version", VERSION))
            .and(form_has(want, &[]))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "sub_1"})))
            .expect(1)
            .mount(&server)
            .await;
        let r = stripe(&server, false)
            .set_quantity("sub_1", 3, prorate, "qty:1")
            .await;
        assert_eq!(r, Ok(()), "{behaviour}");
    }
}

async fn cancel_with(template: ResponseTemplate) -> Result<(), BillingError> {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/v1/subscriptions/sub_1"))
        .and(header("idempotency-key", "cancel:1"))
        .respond_with(template)
        .expect(1)
        .mount(&server)
        .await;
    stripe(&server, false)
        .cancel_subscription("sub_1", "cancel:1")
        .await
}

#[tokio::test]
async fn cancel_404_is_not_found() {
    let missing =
        json!({"error": {"code": "resource_missing", "message": "No such subscription: 'sub_1'"}});
    let r = cancel_with(ResponseTemplate::new(404).set_body_json(missing)).await;
    assert_eq!(r, Err(BillingError::NotFound));
    let ok = json!({"id": "sub_1", "status": "canceled"});
    assert_eq!(
        cancel_with(ResponseTemplate::new(200).set_body_json(ok)).await,
        Ok(())
    );
    // Provider text is never carried, only a stable code.
    let r = cancel_with(ResponseTemplate::new(500).set_body_string("boom")).await;
    assert_eq!(r, Err(BillingError::Other("http_500".into())));
    let card = json!({"error": {"code": "card_declined", "message": "Your card was declined."}});
    let r = cancel_with(ResponseTemplate::new(402).set_body_json(card)).await;
    assert_eq!(r, Err(BillingError::Other("card_declined".into())));
}

fn sign(secret: &str, t: i64, body: &str) -> String {
    let mut m = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    m.update(format!("{t}.{body}").as_bytes());
    m.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn signature_valid_tampered_expired_cases() {
    let (secret, body, t) = ("whsec_test", r#"{"id":"evt_1"}"#, 1_800_000_000);
    let now = Utc.timestamp_opt(t, 0).unwrap();
    let v1 = sign(secret, t, body);
    let check = |h: &str, b: &str, at| verify_stripe_signature(h, b.as_bytes(), secret, at);
    let good = format!("t={t},v1={v1}");
    assert_eq!(check(&good, body, now), Ok(()));
    // Any v1 may match (secret rotation); other schemes are ignored.
    let rotated = format!("t={t},v1={},v0=abc,v1={v1}", "0".repeat(64));
    assert_eq!(check(&rotated, body, now), Ok(()));
    // Tampered body, wrong secret, wrong timestamp.
    assert_eq!(
        check(&good, r#"{"id":"evt_2"}"#, now),
        Err(SigError::Mismatch)
    );
    let other = format!("t={t},v1={}", sign("whsec_other", t, body));
    assert_eq!(check(&other, body, now), Err(SigError::Mismatch));
    let moved = format!("t={},v1={v1}", t + 1);
    assert_eq!(check(&moved, body, now), Err(SigError::Mismatch));
    // 300 s tolerance either side.
    let at = |d: i64| Utc.timestamp_opt(t + d, 0).unwrap();
    assert_eq!(check(&good, body, at(300)), Ok(()));
    assert_eq!(check(&good, body, at(-300)), Ok(()));
    assert_eq!(check(&good, body, at(301)), Err(SigError::Expired));
    assert_eq!(check(&good, body, at(-301)), Err(SigError::Expired));
    // Malformed headers.
    for h in [
        "",
        "v1=abc",
        &format!("t=x,v1={v1}"),
        &format!("t={t}"),
        &format!("t={t},v1=zz"),
    ] {
        assert_eq!(check(h, body, now), Err(SigError::Malformed), "{h}");
    }
}
