use sea_orm_migration::{prelude::*, sea_orm::Statement};

#[derive(DeriveMigrationName)]
pub struct Migration;

// Serves the audit log list (`WHERE organisation_id = $1 ORDER BY created_at DESC, id DESC`).
// Built CONCURRENTLY so writes to audit_events go on while it builds; that cannot run in a
// transaction, hence `use_transaction`. A build that dies leaves an invalid index of this
// name, which `IF NOT EXISTS` would keep: it is dropped first.
const INVALID: &str = "SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid \
    WHERE c.relname = 'audit_events_org_time_idx' AND NOT i.indisvalid";

const UP: &str = "CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_events_org_time_idx \
    ON audit_events (organisation_id, created_at DESC, id DESC)";

const DOWN: &str = "DROP INDEX CONCURRENTLY IF EXISTS audit_events_org_time_idx";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    fn use_transaction(&self) -> Option<bool> {
        Some(false)
    }

    async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
        let db = m.get_connection();
        let check = Statement::from_string(m.get_database_backend(), INVALID);
        if db.query_one_raw(check).await?.is_some() {
            db.execute_unprepared(DOWN).await?;
        }
        db.execute_unprepared(UP).await.map(|_| ())
    }

    async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection()
            .execute_unprepared(DOWN)
            .await
            .map(|_| ())
    }
}
