//! `GET /v1/status`: the public status page's numbers (status-page.md). Anonymous and cheap.
use axum::{extract::State, http::header, response::IntoResponse, Json};
use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{api_error::ApiError, state::AppState};

#[derive(Serialize, ToSchema)]
pub struct ScanStatus {
    /// Scans due now and not yet started.
    pub waiting: i64,
    /// Age of the oldest waiting scan; 0 when none wait.
    pub oldest_wait_seconds: i64,
}

#[derive(Serialize, ToSchema)]
pub struct DeliveryStatus {
    pub sent_24h: i64,
    pub failed_24h: i64,
}

#[derive(Serialize, ToSchema)]
pub struct StatusOut {
    pub scans: ScanStatus,
    pub deliveries: DeliveryStatus,
    pub checked_at: DateTime<Utc>,
}

#[utoipa::path(get, path = "/status", tag = "status",
    responses((status = 200, body = StatusOut, description = "Global counts, no organisation data")))]
async fn show(State(app): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    let s = app.actions.status.run().await?;
    let body = StatusOut {
        scans: ScanStatus {
            waiting: s.scans_waiting,
            oldest_wait_seconds: s.oldest_wait_seconds,
        },
        deliveries: DeliveryStatus {
            sent_24h: s.sent_24h,
            failed_24h: s.failed_24h,
        },
        checked_at: s.checked_at,
    };
    Ok(([(header::CACHE_CONTROL, "public, max-age=30")], Json(body)))
}

pub fn api() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(show))
}
