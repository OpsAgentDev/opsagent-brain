use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

const UP: &str = r#"
-- Watch scans delete their history rows by run; full scans read them by run too.
CREATE INDEX IF NOT EXISTS resource_history_run_id_idx ON resource_history (run_id);
"#;

const DOWN: &str = r#"
DROP INDEX IF EXISTS resource_history_run_id_idx;
"#;

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
