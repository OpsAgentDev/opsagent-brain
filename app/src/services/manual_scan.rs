//! On-demand `full_scan` for a connection, at most once per hour (any `full_scan` run counts).
use axum::http::StatusCode;
use chrono::{DateTime, Duration, Utc};
use loco_rs::app::AppContext;
use opsagent_core::audit::AuditEntry;
use opsagent_core::{
    connection::{Connection, ConnectionStatus as S},
    run::RunKey,
};
use opsagent_ledger::CreateRunOutcome;
use sea_orm::TransactionTrait;
use uuid::Uuid;

use crate::{
    actions::uow::Repos, adapters::db::Pg, api_error::ApiError, models::enum_str,
    services::runs as run_service, workers::full_scan::JOB,
};

pub const WINDOW: Duration = Duration::hours(1);

/// Seconds until a scan is allowed again, if the last one was scheduled within the window.
pub fn retry_after(last: Option<DateTime<Utc>>, now: DateTime<Utc>) -> Option<u64> {
    let left = last? + WINDOW - now;
    (left > Duration::zero()).then(|| u64::try_from(left.num_seconds().max(1)).unwrap_or(1))
}

fn not_scannable(status: &str) -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        "connection_not_scannable",
        format!("A {status} connection cannot be scanned."),
    )
}

// shortcut: ~51 lines, one locked transaction; split if the rate-limit rule gains a second caller.
/// For `actor`: creates the run (`scheduled_at = now`) and a `connection.scan_requested` audit
/// row, or `rate_limited` within the window, or `connection_not_scannable` unless the connection
/// is connected or degraded, then hands the run to the worker. Runs under the connection row
/// lock, so two concurrent requests create one run.
pub async fn request(
    ctx: &AppContext,
    c: &Connection,
    actor: Uuid,
    now: DateTime<Utc>,
) -> Result<CreateRunOutcome, ApiError> {
    let txn = ctx.db.begin().await?;
    let repos = Pg::new(&txn);
    let locked = repos.connections().lock(c.organisation_id, c.id).await?;
    let locked = locked.ok_or_else(ApiError::not_found)?;
    if !matches!(locked.status, S::Connected | S::Degraded) {
        return Err(not_scannable(&enum_str(locked.status)));
    }
    let last = repos
        .runs()
        .last_manual_scan(c.organisation_id, c.id)
        .await?;
    if let Some(secs) = retry_after(last, now) {
        return Err(ApiError::rate_limited(
            "A scan ran for this connection within the last hour.",
            secs,
        ));
    }
    let key = RunKey {
        organisation_id: Some(c.organisation_id),
        connection_id: Some(c.id),
        job_type: JOB.into(),
        scheduled_at: now,
    };
    let out = run_service::mark_new(repos.ledger(), key, now).await?;
    repos
        .audit()
        .record(AuditEntry::member(
            Some(c.organisation_id),
            actor,
            "connection.scan_requested",
            Some(("connection", c.id.to_string())),
        ))
        .await?;
    txn.commit().await?;
    if out.created {
        run_service::hand_off(ctx, &out, JOB, now).await;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_counts_down_the_hour() {
        let now: DateTime<Utc> = "2026-10-22T12:00:00Z".parse().unwrap();
        assert_eq!(retry_after(None, now), None);
        assert_eq!(retry_after(Some(now), now), Some(3600));
        assert_eq!(
            retry_after(Some(now - Duration::minutes(59)), now),
            Some(60)
        );
        assert_eq!(retry_after(Some(now - Duration::minutes(60)), now), None);
        // A future scheduled run (clock skew) still blocks.
        assert!(retry_after(Some(now + Duration::minutes(5)), now).unwrap() > 3600);
    }
}
