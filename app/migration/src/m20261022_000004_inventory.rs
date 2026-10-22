use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

const UP: &str = r#"CREATE TABLE resources (
  id uuid PRIMARY KEY,
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  connection_id uuid NOT NULL REFERENCES connections(id),
  kind text NOT NULL, identity text NOT NULL, name text, region text,
  tags jsonb NOT NULL DEFAULT '{}', attributes jsonb NOT NULL DEFAULT '{}',
  first_seen_at timestamptz NOT NULL DEFAULT now(), last_seen_at timestamptz NOT NULL DEFAULT now(),
  gone_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (connection_id, identity));
CREATE INDEX resources_organisation_id_idx ON resources (organisation_id);
CREATE TABLE resource_history (
  id uuid PRIMARY KEY, resource_id uuid NOT NULL REFERENCES resources(id),
  run_id uuid NOT NULL REFERENCES runs(id), attributes jsonb NOT NULL DEFAULT '{}',
  observed_at timestamptz NOT NULL DEFAULT now(), created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX resource_history_resource_id_idx ON resource_history (resource_id);
CREATE INDEX resource_history_observed_at_idx ON resource_history (observed_at);
CREATE TABLE findings (
  id uuid PRIMARY KEY,
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  connection_id uuid NOT NULL REFERENCES connections(id),
  check_id text NOT NULL, resource_identity text NOT NULL, variant text NOT NULL DEFAULT '',
  severity text NOT NULL,
  status text NOT NULL DEFAULT 'open'
    CHECK (status IN ('open','resolved','accepted','snoozed','flapping')),
  title text NOT NULL, summary text, next_step text, cost_monthly_usd numeric(14,2),
  first_seen_run_id uuid REFERENCES runs(id), last_seen_run_id uuid REFERENCES runs(id),
  resolved_at timestamptz, resolved_reason text, accepted_reason text, accepted_until timestamptz,
  snoozed_until timestamptz, flap_count integer NOT NULL DEFAULT 0, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (connection_id, check_id, resource_identity, variant));
CREATE INDEX findings_organisation_id_idx ON findings (organisation_id);
CREATE TABLE finding_events (
  id uuid PRIMARY KEY, finding_id uuid NOT NULL REFERENCES findings(id),
  run_id uuid NOT NULL REFERENCES runs(id),
  event_type text NOT NULL CHECK (event_type IN ('opened','seen','escalated','deescalated',
    'resolved','reopened','accepted','snoozed','flapping')),
  from_severity text, to_severity text, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (run_id, finding_id, event_type));
CREATE INDEX finding_events_finding_id_idx ON finding_events (finding_id);
CREATE TABLE evidence (
  id uuid PRIMARY KEY, finding_id uuid NOT NULL REFERENCES findings(id),
  run_id uuid NOT NULL REFERENCES runs(id), source text NOT NULL, excerpt text NOT NULL,
  redacted boolean NOT NULL DEFAULT true, expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX evidence_finding_id_idx ON evidence (finding_id);
CREATE INDEX evidence_expires_at_idx ON evidence (expires_at);"#;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection().execute_unprepared(UP).await.map(|_| ())
    }

    async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection().execute_unprepared("DROP TABLE IF EXISTS evidence, finding_events, findings, resource_history, resources CASCADE").await.map(|_| ())
    }
}
