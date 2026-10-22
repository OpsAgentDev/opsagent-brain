use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// Global by design (not per organisation): an address that unsubscribed or ignored confirm
// mails gets no further mail from any organisation. Keyed by hex SHA-256 of the lowercased email.
const UP: &str = r#"CREATE TABLE email_suppressions (
  email_hash text PRIMARY KEY,
  reason text NOT NULL CHECK (reason IN ('unsubscribed','ignored')),
  created_at timestamptz NOT NULL DEFAULT now());"#;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection().execute_unprepared(UP).await.map(|_| ())
    }

    async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS email_suppressions")
            .await
            .map(|_| ())
    }
}
