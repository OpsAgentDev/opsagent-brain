use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    /// Consecutive runs a finding was seen without resolving; ends `flapping` at 7.
    async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection()
            .execute_unprepared(
                "ALTER TABLE findings ADD COLUMN stable_runs integer NOT NULL DEFAULT 0",
            )
            .await
            .map(|_| ())
    }

    async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection()
            .execute_unprepared("ALTER TABLE findings DROP COLUMN IF EXISTS stable_runs")
            .await
            .map(|_| ())
    }
}
