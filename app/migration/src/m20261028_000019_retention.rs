use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

const UP: &str = r#"
-- One global schedule per job (retention.md): organisation and connection both NULL.
CREATE UNIQUE INDEX schedules_global_job_idx ON schedules (job_type)
  WHERE organisation_id IS NULL AND connection_id IS NULL;
-- Run pruning: candidates oldest first, and the foreign-key checks on each deleted run.
CREATE INDEX runs_prunable_idx ON runs (scheduled_at)
  WHERE job_type IN ('watch_scan', 'deliver_alert') OR status = 'skipped';
CREATE INDEX api_calls_raw_run_id_idx ON api_calls_raw (run_id);
CREATE INDEX evidence_run_id_idx ON evidence (run_id);
CREATE INDEX findings_first_seen_run_id_idx ON findings (first_seen_run_id);
CREATE INDEX findings_last_seen_run_id_idx ON findings (last_seen_run_id);
"#;

const DOWN: &str = r#"
DROP INDEX IF EXISTS schedules_global_job_idx, runs_prunable_idx, api_calls_raw_run_id_idx,
  evidence_run_id_idx, findings_first_seen_run_id_idx, findings_last_seen_run_id_idx;
"#;

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
