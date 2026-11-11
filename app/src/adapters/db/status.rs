use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::{DatabaseConnection, FromQueryResult};

use super::ledger_storage::stmt;
use crate::{
    actions::status::{StatusStore, SystemStatus},
    error::{AppError, AppResult},
};

pub struct PgStatus(pub DatabaseConnection);

#[derive(FromQueryResult)]
struct Row {
    waiting: i64,
    oldest: i64,
    sent: i64,
    failed: i64,
}

// tenancy: global aggregates for the public status page; no organisation's rows are returned.
const COUNTS: &str = "SELECT \
    (SELECT count(*) FROM jobs WHERE locked_at IS NULL AND run_at <= $1) AS waiting, \
    (SELECT COALESCE(EXTRACT(EPOCH FROM $1 - min(run_at))::bigint, 0) FROM jobs \
       WHERE locked_at IS NULL AND run_at <= $1) AS oldest, \
    (SELECT count(*) FROM deliveries WHERE created_at > $2 \
       AND status IN ('sent','fallback_email')) AS sent, \
    (SELECT count(*) FROM deliveries WHERE created_at > $2 AND status = 'failed') AS failed";

#[async_trait]
impl StatusStore for PgStatus {
    async fn counts(&self, now: DateTime<Utc>, since: DateTime<Utc>) -> AppResult<SystemStatus> {
        let r = Row::find_by_statement(stmt(COUNTS, vec![now.into(), since.into()]))
            .one(&self.0)
            .await
            .map_err(super::db_err)?
            .ok_or_else(|| AppError::Internal("status counts returned no row".into()))?;
        Ok(SystemStatus {
            scans_waiting: r.waiting,
            oldest_wait_seconds: r.oldest.max(0),
            sent_24h: r.sent,
            failed_24h: r.failed,
            checked_at: now,
        })
    }
}
