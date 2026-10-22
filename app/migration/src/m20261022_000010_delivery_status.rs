use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// `fallback_email`: the briefing went to owners by email instead of Slack. `suppressed`:
// `mail_guard` refused the address, nothing was sent. One organisation-wide schedule per job
// (`deliver_weekly`'s owner summary has no connection).
const UP: &str = r#"ALTER TABLE deliveries DROP CONSTRAINT deliveries_status_check;
ALTER TABLE deliveries ADD CONSTRAINT deliveries_status_check CHECK (status IN
  ('pending','sent','failed','skipped','fallback_email','suppressed'));
CREATE UNIQUE INDEX schedules_org_job_idx ON schedules (organisation_id, job_type)
  WHERE connection_id IS NULL;"#;

// Rows in the new statuses fold back into the nearest old one so the old CHECK can return.
const DOWN: &str = r#"DROP INDEX IF EXISTS schedules_org_job_idx;
ALTER TABLE deliveries DROP CONSTRAINT deliveries_status_check;
UPDATE deliveries SET status = 'sent' WHERE status = 'fallback_email';
UPDATE deliveries SET status = 'skipped' WHERE status = 'suppressed';
ALTER TABLE deliveries ADD CONSTRAINT deliveries_status_check CHECK (status IN
  ('pending','sent','failed','skipped'));"#;

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
