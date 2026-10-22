use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

const UP: &str = r#"CREATE TABLE connections (
  id uuid PRIMARY KEY,
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  provider text NOT NULL, external_account_id text, display_name text,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN
    ('pending','verifying','connected','degraded','revoked','blocked','disconnected')),
  status_reason text, template_version text, scan_time_local time, briefing_time_local time,
  slack_channel_id text, recipients jsonb NOT NULL DEFAULT '[]', api_rate_ceiling integer,
  first_connected_at timestamptz, billable_from timestamptz, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (status IN ('pending','disconnected') OR external_account_id IS NOT NULL));
-- Only claimed accounts are unique, so a pending row cannot squat an account id.
CREATE UNIQUE INDEX connections_provider_account_uniq ON connections (provider, external_account_id)
  WHERE status NOT IN ('pending','disconnected');
CREATE INDEX connections_organisation_id_idx ON connections (organisation_id);
CREATE TABLE connection_credentials (
  connection_id uuid PRIMARY KEY REFERENCES connections(id),
  kind text NOT NULL, ciphertext bytea NOT NULL, nonce bytea NOT NULL,
  kek_version integer NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE connection_verifications (
  id uuid PRIMARY KEY, connection_id uuid NOT NULL REFERENCES connections(id),
  run_id uuid, assume_with_ok boolean, assume_without_denied boolean, policy_matches boolean,
  extra_grants jsonb NOT NULL DEFAULT '[]', missing_grants jsonb NOT NULL DEFAULT '[]',
  outcome text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX connection_verifications_connection_id_idx ON connection_verifications (connection_id);"#;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection().execute_unprepared(UP).await.map(|_| ())
    }

    async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection().execute_unprepared("DROP TABLE IF EXISTS connection_verifications, connection_credentials, connections CASCADE").await.map(|_| ())
    }
}
