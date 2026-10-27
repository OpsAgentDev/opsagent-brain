use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// Pre-signup data, deliberately not tenant-scoped: no organisation_id (same exception as
// waitlist_entries). `forwarded_at` stays NULL until the mail to CONTACT_TO goes out.
const UP: &str = r#"CREATE TABLE contact_messages (
  id uuid PRIMARY KEY,
  name text NOT NULL,
  email text NOT NULL,
  topic text NOT NULL,
  message text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  forwarded_at timestamptz);"#;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection().execute_unprepared(UP).await.map(|_| ())
    }

    async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS contact_messages")
            .await
            .map(|_| ())
    }
}
