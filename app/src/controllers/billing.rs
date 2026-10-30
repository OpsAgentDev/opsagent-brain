use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{DateTime, FixedOffset};
use opsagent_core::billing::{PlanLimits, Tier};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::OrgPath;
use crate::{
    actions::billing::BillingView,
    api_error::{ApiError, ApiJson, Problem},
    middleware::org_scope::OrgScope,
    state::AppState,
};

/// `None` is unlimited.
#[derive(Serialize, ToSchema)]
pub struct Limits {
    pub members: Option<u32>,
    pub integrations: Option<u32>,
    /// Dashboard AI credits per account paid for, per period.
    pub ai_credits: u32,
}

#[derive(Serialize, ToSchema)]
pub struct BillingOut {
    /// `none`, `trialing`, `active`, `past_due`, `paused`, `canceled` or `trial_ended`.
    pub status: String,
    /// `starter`, `team` or `scale`.
    pub tier: Option<String>,
    pub trial_ends_at: Option<DateTime<FixedOffset>>,
    pub current_period_end: Option<DateTime<FixedOffset>>,
    /// Connections billed: at least 1 while subscribed, 0 otherwise.
    pub quantity: i32,
    /// The tier's limits; absent without a tier.
    pub limits: Option<Limits>,
    /// More members or integrations than the tier allows: new ones are refused.
    pub over_limit: bool,
    /// Billing state gates the organisation (`BILLING_ENFORCED`).
    pub enforced: bool,
}

fn view(v: BillingView) -> BillingOut {
    let limits = |l: PlanLimits| Limits {
        members: l.members,
        integrations: l.integrations,
        ai_credits: l.ai_credits,
    };
    BillingOut {
        status: v.status.as_str().into(),
        tier: v.tier.map(|t| Tier::as_str(t).into()),
        trial_ends_at: v.trial_ends_at.map(|t| t.fixed_offset()),
        current_period_end: v.current_period_end.map(|t| t.fixed_offset()),
        quantity: v.quantity,
        limits: v.limits.map(limits),
        over_limit: v.over_limit,
        enforced: v.enforced,
    }
}

#[utoipa::path(get, path = "/orgs/{org}/billing", tag = "billing", params(OrgPath),
    responses((status = 200, body = BillingOut), (status = 404, body = Problem), (status = 503, body = Problem)))]
async fn show(State(app): State<AppState>, scope: OrgScope) -> Result<Json<BillingOut>, ApiError> {
    let b = app.actions.billing.get_billing.run(scope.organisation.id);
    Ok(Json(view(b.await?)))
}

#[derive(Deserialize, ToSchema)]
pub struct CheckoutIn {
    /// `starter`, `team` (default) or `scale`. Only a first subscription on `team` gets the trial.
    pub tier: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct SessionUrl {
    /// The hosted Stripe page; it returns to `WEB_BASE_URL/settings/billing?status=…`.
    pub url: String,
}

#[utoipa::path(post, path = "/orgs/{org}/billing/checkout", tag = "billing", params(OrgPath),
    request_body = CheckoutIn,
    responses((status = 200, body = SessionUrl), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 409, body = Problem, description = "`already_subscribed`"), (status = 422, body = Problem),
        (status = 502, body = Problem), (status = 503, body = Problem)))]
async fn checkout(
    State(app): State<AppState>,
    scope: OrgScope,
    ApiJson(body): ApiJson<CheckoutIn>,
) -> Result<Json<SessionUrl>, ApiError> {
    scope.require_owner()?;
    let start = &app.actions.billing.checkout;
    let url = start.run(&scope, body.tier.as_deref()).await?;
    Ok(Json(SessionUrl { url }))
}

#[utoipa::path(post, path = "/orgs/{org}/billing/portal", tag = "billing", params(OrgPath),
    responses((status = 200, body = SessionUrl), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 409, body = Problem, description = "`no_customer`"), (status = 502, body = Problem),
        (status = 503, body = Problem)))]
async fn portal(
    State(app): State<AppState>,
    scope: OrgScope,
) -> Result<Json<SessionUrl>, ApiError> {
    scope.require_owner()?;
    let url = app
        .actions
        .billing
        .portal
        .run(scope.organisation.id)
        .await?;
    Ok(Json(SessionUrl { url }))
}

#[utoipa::path(post, path = "/webhooks/stripe", tag = "billing",
    request_body(content = String, description = "The Stripe event, verified against `Stripe-Signature`"),
    responses((status = 200, description = "Applied, a repeat, or ignored"),
        (status = 400, body = Problem, description = "`bad_signature` or `bad_payload`"),
        (status = 503, body = Problem)))]
async fn stripe_webhook(
    State(app): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let sig = headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok());
    app.actions.billing.webhook.run(sig, &body).await?;
    Ok(StatusCode::OK)
}

pub fn api() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(show))
        .routes(routes!(checkout))
        .routes(routes!(portal))
        .routes(routes!(stripe_webhook))
}
