//! The Stripe REST adapter for `BillingProvider` (form-encoded, no SDK) and the webhook
//! signature check. The secret key, request bodies and Stripe's error text are never logged
//! or returned; errors carry only a stable code.
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use opsagent_core::billing::{BillingError, BillingProvider, BillingResult, CheckoutRequest};
use reqwest::{Method, StatusCode};
use serde_json::Value;
use sha2::Sha256;
use uuid::Uuid;

pub const API_BASE: &str = "https://api.stripe.com";
/// Webhook timestamps older or newer than this are refused (Stripe's default tolerance).
const TOLERANCE_SECS: u64 = 300;
const TRIAL_DAYS: &str = "14";

/// No `Debug`: it holds the secret key.
#[derive(Clone)]
pub struct StripeSettings {
    pub api_base: String,
    pub secret_key: String,
    /// Sent as `Stripe-Version` on every request.
    pub api_version: String,
    pub automatic_tax: bool,
}

pub struct StripeBilling {
    s: StripeSettings,
    http: reqwest::Client,
}

type Form = Vec<(&'static str, String)>;

impl StripeBilling {
    /// Fails only if the TLS backend cannot initialise.
    pub fn new(s: StripeSettings) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self { s, http })
    }

    /// Sends one request; `idem` goes in `Idempotency-Key`. Returns the parsed body on 2xx.
    async fn call(
        &self,
        method: Method,
        path: &str,
        form: Option<Form>,
        idem: Option<&str>,
    ) -> BillingResult<Value> {
        let url = format!("{}/v1/{path}", self.s.api_base.trim_end_matches('/'));
        let mut req = self
            .http
            .request(method, url)
            .bearer_auth(&self.s.secret_key)
            .header("Stripe-Version", &self.s.api_version);
        if let Some(k) = idem {
            req = req.header("Idempotency-Key", k);
        }
        if let Some(f) = form {
            req = req.form(&f);
        }
        let res = req.send().await.map_err(|_| other("transport"))?;
        let status = res.status();
        let body: Value = res.json().await.unwrap_or(Value::Null);
        if status.is_success() {
            return Ok(body);
        }
        Err(error_of(status, &body))
    }

    async fn post(&self, path: &str, form: Form, idem: &str) -> BillingResult<Value> {
        self.call(Method::POST, path, Some(form), Some(idem)).await
    }
}

fn other(code: &str) -> BillingError {
    BillingError::Other(code.into())
}

/// `NotFound` for a missing object, else Stripe's error code when it is a plain snake_case
/// word, else `http_<status>`.
fn error_of(status: StatusCode, body: &Value) -> BillingError {
    let code = body["error"]["code"].as_str();
    if status == StatusCode::NOT_FOUND || code == Some("resource_missing") {
        return BillingError::NotFound;
    }
    match code {
        Some(c) if c.len() <= 64 && c.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') => {
            other(c)
        }
        _ => BillingError::Other(format!("http_{}", status.as_u16())),
    }
}

/// `body[key]` as a string, else `bad_response`.
fn field(body: &Value, key: &str) -> BillingResult<String> {
    body[key]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| other("bad_response"))
}

#[async_trait]
impl BillingProvider for StripeBilling {
    async fn create_customer(
        &self,
        organisation_id: Uuid,
        name: &str,
        email: &str,
        idem: &str,
    ) -> BillingResult<String> {
        let form = vec![
            ("name", name.to_owned()),
            ("email", email.to_owned()),
            ("metadata[organisation_id]", organisation_id.to_string()),
        ];
        field(&self.post("customers", form, idem).await?, "id")
    }

    async fn checkout_session(&self, r: &CheckoutRequest, idem: &str) -> BillingResult<String> {
        let mut form: Form = vec![
            ("mode", "subscription".into()),
            ("customer", r.customer_id.clone()),
            ("client_reference_id", r.organisation_id.to_string()),
            ("line_items[0][price]", r.price_id.clone()),
            ("line_items[0][quantity]", "1".into()),
            ("payment_method_collection", "always".into()),
            ("allow_promotion_codes", "true".into()),
            ("success_url", r.success_url.clone()),
            ("cancel_url", r.cancel_url.clone()),
        ];
        if r.trial {
            form.push(("subscription_data[trial_period_days]", TRIAL_DAYS.into()));
            let end = "subscription_data[trial_settings][end_behavior][missing_payment_method]";
            form.push((end, "cancel".into()));
        }
        if self.s.automatic_tax {
            form.push(("automatic_tax[enabled]", "true".into()));
            // Stripe Tax needs the existing customer's address, saved from what Checkout collects.
            form.push(("customer_update[address]", "auto".into()));
        }
        field(&self.post("checkout/sessions", form, idem).await?, "url")
    }

    async fn portal_session(&self, customer_id: &str, return_url: &str) -> BillingResult<String> {
        let form = vec![
            ("customer", customer_id.to_owned()),
            ("return_url", return_url.to_owned()),
        ];
        // A fresh key: a portal session is single-use, and every write carries one.
        let idem = Uuid::new_v4().to_string();
        field(
            &self.post("billing_portal/sessions", form, &idem).await?,
            "url",
        )
    }

    async fn set_quantity(
        &self,
        subscription_id: &str,
        quantity: i32,
        prorate: bool,
        idem: &str,
    ) -> BillingResult<()> {
        let path = format!("subscriptions/{}", urlencoding::encode(subscription_id));
        let sub = self.call(Method::GET, &path, None, None).await?;
        let item = field(&sub["items"]["data"][0], "id")?;
        let behaviour = if prorate { "create_prorations" } else { "none" };
        let form = vec![
            ("items[0][id]", item),
            ("items[0][quantity]", quantity.to_string()),
            ("proration_behavior", behaviour.into()),
        ];
        self.post(&path, form, idem).await.map(|_| ())
    }

    async fn cancel_subscription(&self, subscription_id: &str, idem: &str) -> BillingResult<()> {
        let path = format!("subscriptions/{}", urlencoding::encode(subscription_id));
        let r = self.call(Method::DELETE, &path, None, Some(idem)).await;
        r.map(|_| ())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SigError {
    /// No `t=` timestamp or no well-formed `v1=` signature.
    #[error("malformed signature header")]
    Malformed,
    /// The timestamp is more than 300 s from `now`.
    #[error("signature timestamp outside tolerance")]
    Expired,
    #[error("signature mismatch")]
    Mismatch,
}

fn hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Checks a `Stripe-Signature` header (`t=<unix>,v1=<hex>[,v1=…]`) over the raw `body`: some
/// `v1` must equal HMAC-SHA256(`secret`, "{t}.{body}") (constant-time) and `t` must be within
/// 300 s of `now`.
pub fn verify_stripe_signature(
    header: &str,
    body: &[u8],
    secret: &str,
    now: DateTime<Utc>,
) -> Result<(), SigError> {
    let mut t = None;
    let mut sigs = Vec::new();
    for part in header.split(',') {
        match part.trim().split_once('=') {
            Some(("t", v)) => t = Some(v.parse::<i64>().map_err(|_| SigError::Malformed)?),
            Some(("v1", v)) => sigs.extend(hex(v)),
            _ => {}
        }
    }
    // An empty key would let anyone forge signatures; an unset secret verifies nothing.
    if secret.is_empty() {
        return Err(SigError::Mismatch);
    }
    let t = t.ok_or(SigError::Malformed)?;
    if sigs.is_empty() {
        return Err(SigError::Malformed);
    }
    if now.timestamp().abs_diff(t) > TOLERANCE_SECS {
        return Err(SigError::Expired);
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac accepts any key");
    mac.update(format!("{t}.").as_bytes());
    mac.update(body);
    // verify_slice compares in constant time.
    let ok = sigs.iter().any(|s| mac.clone().verify_slice(s).is_ok());
    ok.then_some(()).ok_or(SigError::Mismatch)
}
