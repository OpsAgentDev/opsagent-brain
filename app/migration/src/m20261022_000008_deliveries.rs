use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// `connections.slack_channel_id` already exists (000002). `connections.recipients` (jsonb) stays
// unused: per-connection email routing lives in `recipients` (connection_id set).
const UP: &str = r#"CREATE TABLE integrations (
  id uuid PRIMARY KEY,
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  kind text NOT NULL CHECK (kind IN ('github','slack','terraform','prometheus','k8s')),
  config jsonb NOT NULL DEFAULT '{}',
  ciphertext bytea NOT NULL, nonce bytea NOT NULL, kek_version integer NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked','failing')),
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organisation_id, kind));
CREATE TABLE deliveries (
  id uuid PRIMARY KEY,
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  connection_id uuid REFERENCES connections(id),
  kind text NOT NULL CHECK (kind IN ('briefing','weekly','alert','notice')),
  channel text NOT NULL CHECK (channel IN ('slack','email')),
  target text NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sent','failed','skipped')),
  external_ref text, attempts integer NOT NULL DEFAULT 0, sent_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX deliveries_organisation_id_created_at_idx ON deliveries (organisation_id, created_at);
-- An email recipient is `pending` until the confirm link is used; a member recipient starts
-- `active`. Only the confirm token's hash is stored; unsubscribe tokens are HMACs of the id.
-- A removed member's rows go with the membership.
CREATE TABLE recipients (
  id uuid PRIMARY KEY,
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  connection_id uuid REFERENCES connections(id),
  email text NOT NULL,
  member_id uuid REFERENCES members(id) ON DELETE CASCADE,
  status text NOT NULL CHECK (status IN ('pending','active')),
  confirm_token_hash text, confirm_expires_at timestamptz,
  unsubscribed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT recipients_org_email_connection_uniq
    UNIQUE NULLS NOT DISTINCT (organisation_id, email, connection_id));
CREATE UNIQUE INDEX recipients_confirm_token_hash_uniq ON recipients (confirm_token_hash);"#;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection().execute_unprepared(UP).await.map(|_| ())
    }

    async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS recipients, deliveries, integrations")
            .await
            .map(|_| ())
    }
}
