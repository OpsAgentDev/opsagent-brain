use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// A pending change of the sign-in address: a row with `new_email` set and `email` null, so no
// sign-in lookup (by `email`) ever matches it.
const UP: &str = "ALTER TABLE magic_links ADD COLUMN new_email text;";

const DOWN: &str = "ALTER TABLE magic_links DROP COLUMN new_email;";

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
