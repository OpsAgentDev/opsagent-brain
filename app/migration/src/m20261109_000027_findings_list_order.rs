use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// Serves the findings list order. The CASE must match `RANK` in adapters/db/findings/order.rs exactly,
// or Postgres stops using the index and sorts.
// shortcut: plain CREATE INDEX blocks writes to findings while it builds, fine at alpha size; use
// CONCURRENTLY outside a transaction once findings is large.
const UP: &str = "CREATE INDEX findings_list_order_idx ON findings (organisation_id, status, \
    (CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 \
    WHEN 'low' THEN 3 ELSE 4 END), created_at, id);";

const DOWN: &str = "DROP INDEX findings_list_order_idx;";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection().execute_unprepared(UP).await.map(|_| ())
    }

    async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection()
            .execute_unprepared(DOWN)
            .await
            .map(|_| ())
    }
}
