use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// Where the organisation's sign-up came from (utm_*, referrer, landing path); null for older rows.
const UP: &str = "ALTER TABLE organisations ADD COLUMN signup_source jsonb;";

const DOWN: &str = "ALTER TABLE organisations DROP COLUMN signup_source;";

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
