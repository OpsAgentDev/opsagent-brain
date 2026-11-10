use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// Double opt-in replaces Turnstile on the waitlist: an entry is verified once its emailed link is
// used. Only the link token's hash is stored.
const UP: &str = "ALTER TABLE waitlist_entries ADD COLUMN verify_token_hash text UNIQUE, \
    ADD COLUMN verified_at timestamptz;";

const DOWN: &str =
    "ALTER TABLE waitlist_entries DROP COLUMN verified_at, DROP COLUMN verify_token_hash;";

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
