//! The operator notice's read of the last day's failures across all organisations.
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::{DatabaseConnection, FromQueryResult};

use super::{db_err, ledger_storage::stmt};
use crate::{
    actions::runs::{FailureCounts, Failures},
    error::AppResult,
};

pub struct PgFailures(pub DatabaseConnection);

#[derive(FromQueryResult)]
struct KindCount {
    kind: String,
    n: i64,
}

impl PgFailures {
    async fn counts(&self, sql: &str, since: DateTime<Utc>) -> AppResult<Vec<(String, i64)>> {
        let rows = KindCount::find_by_statement(stmt(sql, vec![since.into()]))
            .all(&self.0)
            .await
            .map_err(db_err)?;
        Ok(rows.into_iter().map(|r| (r.kind, r.n)).collect())
    }
}

#[async_trait]
impl FailureCounts for PgFailures {
    async fn since(&self, since: DateTime<Utc>) -> AppResult<Failures> {
        // A dead job stays locked with no owner (`PgQueue::fail`); locked_at is its last attempt.
        let dead = "SELECT kind, count(*) AS n FROM jobs \
             WHERE locked_at IS NOT NULL AND locked_by IS NULL AND locked_at >= $1 \
             GROUP BY kind ORDER BY kind";
        // tenancy: the operator's aggregate across all organisations; counts and kinds only.
        let failed = "SELECT job_type AS kind, count(*) AS n FROM runs \
             WHERE status = 'failed' AND finished_at >= $1 GROUP BY job_type ORDER BY job_type";
        Ok(Failures {
            dead_jobs: self.counts(dead, since).await?,
            failed_runs: self.counts(failed, since).await?,
        })
    }
}
