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
}
