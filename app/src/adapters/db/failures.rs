//! The operator notice's read of the last day's failures and sign-ups across all organisations.
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use sea_orm::{DatabaseConnection, FromQueryResult};

use super::{db_err, ledger_storage::stmt};
use crate::{
    actions::runs::{FailureCounts, Failures, Signups, WeekCounts, MRR_CASE},
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

#[derive(FromQueryResult)]
struct Paid {
    n: i64,
    mrr: i64,
}

impl PgFailures {
    async fn count(&self, sql: &str, since: DateTime<Utc>) -> AppResult<i64> {
        let row = Count::find_by_statement(stmt(sql, vec![since.into()]))
            .one(&self.0)
            .await
            .map_err(db_err)?;
        Ok(row.map_or(0, |r| r.n))
    }

    async fn count2(&self, sql: &str, from: DateTime<Utc>, to: DateTime<Utc>) -> AppResult<i64> {
        let row = Count::find_by_statement(stmt(sql, vec![from.into(), to.into()]))
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
    async fn week_until(&self, until: DateTime<Utc>) -> AppResult<WeekCounts> {
        let from = until - Duration::days(7);
        // Internal organisations: an owner whose email ends in @opsagent.dev.
        let external = "NOT EXISTS (SELECT 1 FROM members m JOIN users u ON u.id = m.user_id \
             WHERE m.organisation_id = o.id AND m.role = 'owner' AND lower(u.email) LIKE '%@opsagent.dev')";
        // tenancy: the operator's aggregate across all organisations; counts and sources only.
        let by_source = format!(
            "SELECT coalesce(nullif(o.signup_source->>'utm_source', ''), 'direct') AS kind, count(*) AS n \
             FROM organisations o WHERE o.created_at >= $1 AND o.created_at < $2 AND {external} \
             GROUP BY 1 ORDER BY n DESC, kind"
        );
        let rows = KindCount::find_by_statement(stmt(&by_source, vec![from.into(), until.into()]))
            .all(&self.0)
            .await
            .map_err(db_err)?;
        // tenancy: the operator's aggregate across all organisations; counts only.
        let trials = format!(
            "SELECT count(*) AS n FROM organisations o WHERE {external} \
             AND o.trial_ends_at - interval '14 days' >= $1 AND o.trial_ends_at - interval '14 days' < $2"
        );
        // tenancy: the operator's aggregate across all organisations; counts only.
        let activated = format!(
            "SELECT count(*) AS n FROM organisations o WHERE o.created_at >= $1 AND o.created_at < $2 AND {external} \
             AND EXISTS (SELECT 1 FROM connections c WHERE c.organisation_id = o.id AND c.first_connected_at IS NOT NULL) \
             AND EXISTS (SELECT 1 FROM findings f WHERE f.organisation_id = o.id)"
        );
        // tenancy: the operator's aggregate across all organisations; counts only.
        let paid = format!(
            "SELECT count(*) AS n, coalesce(sum(({MRR_CASE}) * coalesce(billing_quantity, 0)), 0)::bigint AS mrr \
             FROM organisations o WHERE o.billing_status = 'active' AND {external}"
        );
        let paid = Paid::find_by_statement(stmt(&paid, vec![]))
            .one(&self.0)
            .await
            .map_err(db_err)?;
        Ok(WeekCounts {
            new_orgs_by_source: rows.into_iter().map(|r| (r.kind, r.n)).collect(),
            trials_started: self.count2(&trials, from, until).await?,
            activated: self.count2(&activated, from, until).await?,
            converted_to_paid: paid.as_ref().map_or(0, |p| p.n),
            mrr_cents: paid.map_or(0, |p| p.mrr),
        })
    }
}
