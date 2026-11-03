//! `/v1/orgs/{org}/human-reviews`: paid human review requests (human-review.md).
use axum::{extract::State, http::StatusCode, Json};
use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::OrgPath;
use crate::{
    actions::human_reviews::{ReviewInput, OFFERS},
    api_error::{ApiError, ApiJson, Problem},
    middleware::org_scope::OrgScope,
    state::AppState,
};

#[derive(Serialize, ToSchema)]
pub struct HumanReviewOffer {
    /// `finding` or `account`.
    pub kind: String,
    pub price_cents: i32,
    pub title: String,
    pub description: String,
}

#[derive(Serialize, ToSchema)]
pub struct HumanReviewRequestOut {
    pub id: Uuid,
    pub kind: String,
    pub finding_id: Option<Uuid>,
    pub connection_id: Option<Uuid>,
    /// The finding title or connection name when asked.
    pub target_label: String,
    pub note: Option<String>,
    /// The price when asked.
    pub price_cents: i32,
    pub requester_email: String,
    /// `invoice` (invoiced outside the product), `pending` (awaiting Stripe payment) or `paid`.
    pub payment: String,
    pub paid_at: Option<DateTime<FixedOffset>>,
    pub created_at: DateTime<FixedOffset>,
}

#[derive(Serialize, ToSchema)]
pub struct HumanReviews {
    pub offers: Vec<HumanReviewOffer>,
    /// The latest 50, newest first.
    pub requests: Vec<HumanReviewRequestOut>,
}

#[utoipa::path(get, path = "/orgs/{org}/human-reviews", tag = "human-reviews", params(OrgPath),
    responses((status = 200, body = HumanReviews), (status = 404, body = Problem)))]
async fn list(
    State(app): State<AppState>,
    scope: OrgScope,
) -> Result<Json<HumanReviews>, ApiError> {
    let got = app
        .actions
        .human_reviews
        .list
        .run(scope.organisation.id)
        .await?;
    Ok(Json(HumanReviews {
        offers: OFFERS
            .iter()
            .map(|o| HumanReviewOffer {
                kind: o.kind.as_str().into(),
                price_cents: o.price_cents,
                title: o.title.into(),
                description: o.description.into(),
            })
            .collect(),
        requests: got
            .into_iter()
            .map(|r| HumanReviewRequestOut {
                id: r.id,
                kind: r.kind.as_str().into(),
                finding_id: r.finding_id,
                connection_id: r.connection_id,
                target_label: r.target_label,
                note: r.note,
                price_cents: r.price_cents,
                requester_email: r.requester_email,
                payment: r.payment.as_str().into(),
                paid_at: r.paid_at.map(|t| t.fixed_offset()),
                created_at: r.created_at.fixed_offset(),
            })
            .collect(),
    }))
}

#[derive(Deserialize, ToSchema)]
pub struct HumanReviewIn {
    /// `finding` (needs `finding_id`) or `account` (needs `connection_id`).
    pub kind: String,
    pub finding_id: Option<Uuid>,
    pub connection_id: Option<Uuid>,
    /// Up to 2000 characters.
    pub note: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct HumanReviewCreated {
    pub id: Uuid,
    /// The hosted Stripe Checkout page to pay on; null when Stripe is not configured (invoiced).
    pub checkout_url: Option<String>,
}

/// Owner only. Allowed while the organisation is read-only: it is paid separately. 502
/// `billing_unavailable` when Stripe fails.
#[utoipa::path(post, path = "/orgs/{org}/human-reviews", tag = "human-reviews", params(OrgPath),
    request_body = HumanReviewIn,
    responses((status = 201, body = HumanReviewCreated), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 422, body = Problem), (status = 429, body = Problem), (status = 502, body = Problem)))]
async fn create(
    State(app): State<AppState>,
    scope: OrgScope,
    ApiJson(body): ApiJson<HumanReviewIn>,
) -> Result<(StatusCode, Json<HumanReviewCreated>), ApiError> {
    scope.require_owner()?;
    let input = ReviewInput {
        kind: body.kind,
        finding_id: body.finding_id,
        connection_id: body.connection_id,
        note: body.note,
    };
    let request = &app.actions.human_reviews.request;
    let (id, checkout_url) = request.run(&scope, input).await?;
    let created = HumanReviewCreated { id, checkout_url };
    Ok((StatusCode::CREATED, Json(created)))
}

pub fn api() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(list, create))
}
