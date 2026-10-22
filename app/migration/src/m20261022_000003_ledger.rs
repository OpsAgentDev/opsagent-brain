use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

const UP: &str = r#"CREATE TABLE runs (
  id uuid PRIMARY KEY,
  organisation_id uuid REFERENCES organisations(id),
  connection_id uuid REFERENCES connections(id),
  job_type text NOT NULL, scheduled_at timestamptz NOT NULL,
  status text NOT NULL DEFAULT 'queued'
    CHECK (status IN ('queued','running','partial','done','failed','skipped')),
  checkpoint jsonb NOT NULL DEFAULT '{}', fence bigint NOT NULL DEFAULT 0,
  partial_reason text, attempts integer NOT NULL DEFAULT 0, next_attempt_at timestamptz,
  started_at timestamptz, finished_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE UNIQUE INDEX runs_idempotency_key ON runs
  (organisation_id, connection_id, job_type, scheduled_at) NULLS NOT DISTINCT;
CREATE INDEX runs_due_idx ON runs (status, next_attempt_at);
CREATE TABLE side_effects (
  id uuid PRIMARY KEY, run_id uuid NOT NULL REFERENCES runs(id), effect_key text NOT NULL,
  status text NOT NULL CHECK (status IN ('started','done')), external_ref text,
  started_at timestamptz, done_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (run_id, effect_key));
CREATE TABLE schedules (
  id uuid PRIMARY KEY,
  organisation_id uuid REFERENCES organisations(id),
  connection_id uuid REFERENCES connections(id),
  job_type text NOT NULL, cron_local text NOT NULL, timezone text NOT NULL DEFAULT 'UTC',
  enabled boolean NOT NULL DEFAULT true, next_due_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX schedules_organisation_id_idx ON schedules (organisation_id);
CREATE UNIQUE INDEX schedules_connection_job_idx ON schedules (connection_id, job_type);
CREATE INDEX schedules_next_due_at_idx ON schedules (next_due_at) WHERE enabled;
CREATE TABLE api_call_stats (
  id uuid PRIMARY KEY, run_id uuid NOT NULL REFERENCES runs(id),
  provider text NOT NULL, service text NOT NULL, action text NOT NULL, region text,
  outcome text NOT NULL, count bigint NOT NULL DEFAULT 0, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX api_call_stats_run_id_idx ON api_call_stats (run_id);
CREATE TABLE api_calls_raw (
  id uuid PRIMARY KEY, run_id uuid NOT NULL REFERENCES runs(id),
  provider text NOT NULL, service text NOT NULL, action text NOT NULL, region text,
  outcome text NOT NULL, detail jsonb NOT NULL DEFAULT '{}',
  called_at timestamptz NOT NULL DEFAULT now(), created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX api_calls_raw_called_at_idx ON api_calls_raw (called_at);"#;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection().execute_unprepared(UP).await.map(|_| ())
    }

    async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection().execute_unprepared("DROP TABLE IF EXISTS api_calls_raw, api_call_stats, schedules, side_effects, runs CASCADE").await.map(|_| ())
    }
}
