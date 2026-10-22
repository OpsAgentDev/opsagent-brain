use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// Keyed by hex SHA-256 of the lowercased email. Three kinds of row:
// - `unsubscribed`: global (organisation_id NULL), permanent; no mail from any organisation.
// - `ignored`: one organisation, 90 days; that organisation's confirm mails went unconfirmed.
// - `confirm_blocked`: global, 90 days; blocks confirm mails only (never deliveries to
//   recipients who confirmed), after unconfirmed mails from several distinct owning users.
const UP: &str = r#"CREATE TABLE email_suppressions (
  id uuid PRIMARY KEY,
  organisation_id uuid REFERENCES organisations(id),
  email_hash text NOT NULL,
  reason text NOT NULL CHECK (reason IN ('unsubscribed','ignored','confirm_blocked')),
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((reason = 'unsubscribed' AND organisation_id IS NULL AND expires_at IS NULL)
      OR (reason = 'ignored' AND organisation_id IS NOT NULL AND expires_at IS NOT NULL)
      OR (reason = 'confirm_blocked' AND organisation_id IS NULL AND expires_at IS NOT NULL)),
  CONSTRAINT email_suppressions_org_email_uniq
    UNIQUE NULLS NOT DISTINCT (organisation_id, email_hash));"#;

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
