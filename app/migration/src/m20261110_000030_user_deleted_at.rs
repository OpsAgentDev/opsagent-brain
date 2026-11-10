use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// Erased accounts stay as anonymised rows (audit and history keep their ids); lookups skip them.
const UP: &str = "ALTER TABLE users ADD COLUMN deleted_at timestamptz;";

const DOWN: &str = "ALTER TABLE users DROP COLUMN deleted_at;";

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
