//! On-demand `full_scan` for a connection, at most once per hour (any `full_scan` run counts).
use chrono::{DateTime, Duration, Utc};
use opsagent_core::run::RunKey;
use opsagent_ledger::{CreateRunOutcome, Storage};
use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, QuerySelect,
    TransactionTrait,
};

use crate::{
    api_error::ApiError,
    models::{
        _entities::{connections, runs},
        ledger_storage::PgStorage,
    },
    workers::full_scan::JOB,
};

pub const WINDOW: Duration = Duration::hours(1);

/// Seconds until a scan is allowed again, if the last one was scheduled within the window.
pub fn retry_after(last: Option<DateTime<Utc>>, now: DateTime<Utc>) -> Option<u64> {
    let left = last? + WINDOW - now;
    (left > Duration::zero()).then(|| u64::try_from(left.num_seconds().max(1)).unwrap_or(1))
}

/// Creates the run (`scheduled_at = now`), or `rate_limited` within the window. The check and
/// the insert hold the connection row lock, so two concurrent requests create one run.
pub async fn request(
    db: &DatabaseConnection,
    c: &connections::Model,
    now: DateTime<Utc>,
) -> Result<CreateRunOutcome, ApiError> {
    let txn = db.begin().await?;
    connections::Entity::find_by_id(c.id)
        .lock_exclusive()
        .one(&txn)
        .await?;
    let last = runs::Entity::find()
        .filter(runs::Column::ConnectionId.eq(c.id))
        .filter(runs::Column::JobType.eq(JOB))
        .order_by_desc(runs::Column::ScheduledAt)
        .one(&txn)
        .await?
        .map(|r| r.scheduled_at.with_timezone(&Utc));
    if let Some(secs) = retry_after(last, now) {
        return Err(ApiError::rate_limited(
            "A scan ran for this connection within the last hour.",
            secs,
        ));
    }
    let storage = PgStorage::new(txn);
    let out = storage
        .create_run(RunKey {
            organisation_id: Some(c.organisation_id),
            connection_id: Some(c.id),
            job_type: JOB.into(),
            scheduled_at: now,
        })
        .await?;
    storage.into_inner().commit().await?;
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
