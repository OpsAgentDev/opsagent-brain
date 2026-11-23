use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// The owner's opt-in to hear about other Binary Labs products; off until they tick it.
const UP: &str = "ALTER TABLE users ADD COLUMN marketing_ok boolean NOT NULL DEFAULT false;";

const DOWN: &str = "ALTER TABLE users DROP COLUMN marketing_ok;";

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
