use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// Where a magic link sends the user after sign-in (the OAuth consent page); NULL means the
// dashboard. Only values `consent_return_to` accepts are stored.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection()
            .execute_unprepared("ALTER TABLE magic_links ADD COLUMN return_to text")
            .await
            .map(|_| ())
    }

    async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection()
            .execute_unprepared("ALTER TABLE magic_links DROP COLUMN IF EXISTS return_to")
            .await
            .map(|_| ())
    }
}
