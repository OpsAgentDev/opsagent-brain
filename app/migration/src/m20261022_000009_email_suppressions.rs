use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// An explicit unsubscribe is global (organisation_id NULL, no expiry): that address gets no
// mail from any organisation. Ignored confirm mails suppress the address for that organisation
// only, for 90 days, so one organisation cannot silence an address for another. Keyed by hex
// SHA-256 of the lowercased email.
const UP: &str = r#"CREATE TABLE email_suppressions (
  id uuid PRIMARY KEY,
  organisation_id uuid REFERENCES organisations(id),
  email_hash text NOT NULL,
  reason text NOT NULL CHECK (reason IN ('unsubscribed','ignored')),
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((reason = 'unsubscribed' AND organisation_id IS NULL AND expires_at IS NULL)
      OR (reason = 'ignored' AND organisation_id IS NOT NULL AND expires_at IS NOT NULL)),
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
