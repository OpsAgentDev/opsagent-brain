//! `POST /v1/waitlist`: anonymous sign-up for the landing page.
use axum::{extract::State, http::StatusCode};
use serde::Deserialize;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    actions::waitlist::{JoinInput, JoinOutcome},
    adapters::client_ip::ClientIp,
    api_error::{ApiError, ApiJson},
    state::AppState,
};

#[derive(Deserialize, ToSchema)]
pub struct WaitlistRequest {
    pub email: String,
    /// Where the form sat, at most 64 characters (`landing-hero`, `landing-footer`).
    pub source: Option<String>,
}

/// Always 202 for a valid address, new or already listed, so the response never reveals which.
#[utoipa::path(post, path = "/waitlist", tag = "waitlist", request_body = WaitlistRequest,
    responses(
        (status = 202, description = "On the waitlist"),
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

pub fn api() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(join))
}
