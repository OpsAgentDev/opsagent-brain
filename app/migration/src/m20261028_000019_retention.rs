use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

const UP: &str = r#"
-- One global schedule per job (retention.md): organisation and connection both NULL.
CREATE UNIQUE INDEX schedules_global_job_idx ON schedules (job_type)
  WHERE organisation_id IS NULL AND connection_id IS NULL;
"#;

const DOWN: &str = r#"
DROP INDEX IF EXISTS schedules_global_job_idx;
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
