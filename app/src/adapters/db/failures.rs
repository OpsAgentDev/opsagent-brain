//! The operator notice's read of the last day's failures and sign-ups across all organisations.
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::{DatabaseConnection, FromQueryResult};

use super::{db_err, ledger_storage::stmt};
use crate::{
    actions::runs::{FailureCounts, Failures, Signups},
    error::AppResult,
};

pub struct PgFailures(pub DatabaseConnection);

#[derive(FromQueryResult)]
struct KindCount {
    kind: String,
    n: i64,
}

#[derive(FromQueryResult)]
struct Count {
    n: i64,
}

impl PgFailures {
    async fn count(&self, sql: &str, since: DateTime<Utc>) -> AppResult<i64> {
        let row = Count::find_by_statement(stmt(sql, vec![since.into()]))
            .one(&self.0)
            .await
            .map_err(db_err)?;
        Ok(row.map_or(0, |r| r.n))
    }

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

    async fn signups_since(&self, since: DateTime<Utc>) -> AppResult<Signups> {
        // tenancy: the operator's aggregate across all organisations; counts only.
        let users = "SELECT count(*) AS n FROM users WHERE created_at >= $1";
        // tenancy: the operator's aggregate across all organisations; counts only.
        let orgs = "SELECT count(*) AS n FROM organisations WHERE created_at >= $1";
        // tenancy: the waitlist belongs to no organisation; counts only.
        let waitlist = "SELECT count(*) AS n FROM waitlist_entries WHERE created_at >= $1";
        Ok(Signups {
            users: self.count(users, since).await?,
            organisations: self.count(orgs, since).await?,
            waitlist: self.count(waitlist, since).await?,
        })
    }
}
