use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    repo::RepoResult,
    retention::{RetentionRepo, TtlTable},
};
use sea_orm::ConnectionTrait;

use super::ledger_storage::stmt;
use super::{db_err, Conn, Pg};

/// The column each table expires on.
fn expiry_column(t: TtlTable) -> &'static str {
    match t {
        TtlTable::ResourceHistory => "observed_at",
        TtlTable::ApiCallsRaw => "called_at",
        TtlTable::Sessions => "expiry_date",
        _ => "expires_at",
    }
}

/// The prunable-run rule (retention.md, goal 3), oldest first.
// tenancy: global pruning; every organisation's operational runs go, by age and kind alone.
const PRUNE_RUNS: &str = "WITH picked AS ( \
  SELECT r.id FROM runs r \
  WHERE r.scheduled_at < $1 \
    AND r.status IN ('done', 'partial', 'failed', 'skipped') \
    AND (r.job_type IN ('watch_scan', 'deliver_alert') OR r.status = 'skipped') \
    AND NOT EXISTS (SELECT 1 FROM finding_events e WHERE e.run_id = r.id) \
    AND NOT EXISTS (SELECT 1 FROM evidence v WHERE v.run_id = r.id) \
    AND NOT EXISTS (SELECT 1 FROM findings f WHERE f.first_seen_run_id = r.id) \
    AND NOT EXISTS (SELECT 1 FROM findings f WHERE f.last_seen_run_id = r.id) \
    AND NOT EXISTS (SELECT 1 FROM side_effects s \
                    WHERE s.run_id = r.id AND s.effect_key LIKE 'alert:baseline%') \
  ORDER BY r.scheduled_at LIMIT $2), \
se AS (DELETE FROM side_effects WHERE run_id IN (SELECT id FROM picked)), \
st AS (DELETE FROM api_call_stats WHERE run_id IN (SELECT id FROM picked)), \
raw AS (DELETE FROM api_calls_raw WHERE run_id IN (SELECT id FROM picked)), \
rh AS (DELETE FROM resource_history WHERE run_id IN (SELECT id FROM picked)) \
DELETE FROM runs WHERE id IN (SELECT id FROM picked)";

#[async_trait]
impl<C: Conn> RetentionRepo for Pg<C> {
    async fn delete_expired(
        &self,
        table: TtlTable,
        cutoff: DateTime<Utc>,
        batch: u64,
    ) -> RepoResult<u64> {
        let (t, col) = (table.name(), expiry_column(table));
        // tenancy: global TTL; every organisation's expired rows go, by age alone.
        let sql = format!(
            "DELETE FROM {t} WHERE ctid IN (SELECT ctid FROM {t} WHERE {col} < $1 LIMIT $2)"
        );
        let done = self
            .db()
            .execute_raw(stmt(&sql, vec![cutoff.into(), (batch as i64).into()]))
            .await
            .map_err(db_err)?;
        Ok(done.rows_affected())
    }

    async fn prune_runs(&self, older_than: DateTime<Utc>, batch: u64) -> RepoResult<u64> {
        // One statement, so one transaction; the runs' NO ACTION foreign keys are checked at
        // its end, after the sibling CTEs removed the dependents (`jobs` cascades).
        let done = self
            .db()
            .execute_raw(stmt(
                PRUNE_RUNS,
                vec![older_than.into(), (batch as i64).into()],
            ))
            .await
            .map_err(db_err)?;
        Ok(done.rows_affected())
    }
}
