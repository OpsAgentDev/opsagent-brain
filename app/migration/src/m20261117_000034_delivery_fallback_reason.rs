use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// Why a `fallback_email` row went by email instead of Slack. Null on every other row and on
// rows written before this column.
const UP: &str = "ALTER TABLE deliveries ADD COLUMN fallback_reason text
  CHECK (fallback_reason IN ('slack_not_connected','no_channel','slack_failed'));";

const DOWN: &str = "ALTER TABLE deliveries DROP COLUMN fallback_reason;";

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
