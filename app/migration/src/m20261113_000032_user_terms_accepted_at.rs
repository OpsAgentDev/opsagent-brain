use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// When the user agreed to the Terms and the Privacy Policy; null until they do.
const UP: &str = "ALTER TABLE users ADD COLUMN terms_accepted_at timestamptz;";

const DOWN: &str = "ALTER TABLE users DROP COLUMN terms_accepted_at;";

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
