//! `POST /v1/waitlist`: anonymous sign-up for the landing page, confirmed by email (double
//! opt-in) rather than a Turnstile check; `POST /v1/waitlist/verify` takes the emailed token.
use axum::{extract::State, http::StatusCode};
use serde::Deserialize;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    actions::waitlist::{JoinInput, JoinOutcome},
    adapters::client_ip::ClientIp,
    api_error::{ApiError, ApiJson, Problem},
    state::AppState,
};

#[derive(Deserialize, ToSchema)]
pub struct WaitlistRequest {
    pub email: String,
    /// Where the form sat, at most 64 characters (`landing-hero`, `landing-footer`).
    pub source: Option<String>,
    /// Ignored: the waitlist no longer uses Turnstile. Accepted so older pages keep working.
    pub turnstile_token: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct WaitlistVerifyRequest {
    /// The token from the confirmation email's link.
    pub token: String,
}

/// Always 202 for a valid address, new or already listed, so the response never reveals which.
#[utoipa::path(post, path = "/waitlist", tag = "waitlist", request_body = WaitlistRequest,
    responses(
        (status = 202, description = "Listed, unverified until the emailed link is used"),
        (status = 422, description = "Invalid email or source"),
        (status = 429, description = "Rate limited (10 per client IP per hour)")))]
async fn join(
    State(app): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(body): ApiJson<WaitlistRequest>,
) -> Result<StatusCode, ApiError> {
    let input = JoinInput {
        email: body.email,
        source: body.source,
        client_ip: ip,
    };
    match app.actions.waitlist.join.run(input).await? {
        JoinOutcome::Accepted => Ok(StatusCode::ACCEPTED),
        JoinOutcome::Invalid => Err(ApiError::invalid("Enter a valid email address.")),
        JoinOutcome::RateLimited => Err(ApiError::rate_limited(
            "Too many requests. Try again later.",
            3600,
        )),
    }
}

#[utoipa::path(post, path = "/waitlist/verify", tag = "waitlist", request_body = WaitlistVerifyRequest,
    responses(
        (status = 204, description = "Email confirmed"),
        (status = 410, body = Problem, description = "`waitlist_link_invalid`: unknown, replaced or already used")))]
async fn verify(
    State(app): State<AppState>,
    ApiJson(body): ApiJson<WaitlistVerifyRequest>,
) -> Result<StatusCode, ApiError> {
    if app.actions.waitlist.verify.run(&body.token).await? {
        return Ok(StatusCode::NO_CONTENT);
    }
    Err(crate::error::AppError::Gone("waitlist_link_invalid").into())
}

pub fn api() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(join))
        .routes(routes!(verify))
}
