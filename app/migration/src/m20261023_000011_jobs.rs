use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// The job queue (app-shell.md, "Jobs table"), drained with FOR UPDATE SKIP LOCKED. Global, not
// tenant-scoped: a job names its run, and the run names its organisation.
const UP: &str = r#"CREATE TABLE jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind text NOT NULL,
  args jsonb NOT NULL,
  run_id uuid REFERENCES runs(id) ON DELETE CASCADE,
  run_at timestamptz NOT NULL,
  attempts int NOT NULL DEFAULT 0,
  max_attempts int NOT NULL,
  locked_at timestamptz,
  locked_by text,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX jobs_ready ON jobs (run_at) WHERE locked_at IS NULL;
CREATE UNIQUE INDEX jobs_one_per_run ON jobs (run_id) WHERE run_id IS NOT NULL;"#;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection().execute_unprepared(UP).await.map(|_| ())
    }

    async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS jobs")
            .await
            .map(|_| ())
    }
}
