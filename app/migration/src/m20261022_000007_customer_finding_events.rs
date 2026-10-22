use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    /// Customer actions (accept, snooze, reopen) are finding events without a run.
    async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection()
            .execute_unprepared("ALTER TABLE finding_events ALTER COLUMN run_id DROP NOT NULL")
            .await
            .map(|_| ())
    }

    async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection()
            .execute_unprepared(
                "DELETE FROM finding_events WHERE run_id IS NULL; \
                 ALTER TABLE finding_events ALTER COLUMN run_id SET NOT NULL",
            )
            .await
            .map(|_| ())
    }
}
