//! `POST /v1/contact`: anonymous contact form, forwarded to the fixed `CONTACT_TO` address.
use axum::{extract::State, http::StatusCode};
use serde::Deserialize;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    actions::contact::{ContactInput, ContactOutcome},
    adapters::client_ip::ClientIp,
    api_error::{ApiError, ApiJson},
    state::AppState,
};

#[derive(Deserialize, ToSchema)]
pub struct ContactRequest {
    /// 1 to 100 characters, no control characters.
    pub name: String,
    pub email: String,
    /// One of `general`, `sales`, `support`, `security`, `partnership`.
    pub topic: String,
    /// 10 to 5000 characters.
    pub message: String,
    /// Honeypot: real visitors leave it empty; a filled value is answered 202 and dropped.
    pub website: Option<String>,
}

#[utoipa::path(post, path = "/contact", tag = "contact", request_body = ContactRequest,
    responses(
        (status = 202, description = "Received"),
        (status = 422, description = "Invalid name, email, topic or message"),
        (status = 429, description = "Rate limited (5 per client IP per hour)")))]
async fn send(
    State(app): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(body): ApiJson<ContactRequest>,
) -> Result<StatusCode, ApiError> {
    let input = ContactInput {
        name: body.name,
        email: body.email,
        topic: body.topic,
        message: body.message,
        website: body.website,
        client_ip: ip,
    };
    match app.actions.contact.send.run(input).await? {
        ContactOutcome::Accepted => Ok(StatusCode::ACCEPTED),
        ContactOutcome::Invalid => Err(ApiError::invalid(
            "Check the highlighted fields and try again.",
        )),
        ContactOutcome::RateLimited => Err(ApiError::rate_limited(
            "Too many requests. Try again later.",
            3600,
        )),
    }
}

pub fn api() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(send))
}
