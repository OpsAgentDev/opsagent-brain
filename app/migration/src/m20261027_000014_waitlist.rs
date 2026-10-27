use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// Pre-signup data, deliberately not tenant-scoped: no organisation_id (DECISIONS 2026-10-27).
// `email` is stored trimmed and lowercased; `confirmation_sent_at` stays NULL until the mail goes.
const UP: &str = r#"CREATE TABLE waitlist_entries (
  id uuid PRIMARY KEY,
  email text NOT NULL UNIQUE,
  source text,
  created_at timestamptz NOT NULL DEFAULT now(),
  confirmation_sent_at timestamptz);"#;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection().execute_unprepared(UP).await.map(|_| ())
    }

    async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS waitlist_entries")
            .await
            .map(|_| ())
    }
}
