use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// dashboard-ai.md, Data model: the AI switch and top-up balance, the evidence hash explanations
// are cached on, BYOK keys, metering, once-only notices and chat history (text only).
const UP: &str = r#"
ALTER TABLE organisations
  ADD COLUMN ai_enabled boolean NOT NULL DEFAULT false,
  ADD COLUMN ai_topup_balance numeric NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN evidence_hash text;
CREATE TABLE model_keys (
  id uuid PRIMARY KEY,
  organisation_id uuid NOT NULL UNIQUE REFERENCES organisations(id),
  provider text NOT NULL CHECK (provider IN ('anthropic','openai')),
  last4 text NOT NULL,
  ciphertext bytea NOT NULL,
  nonce bytea NOT NULL,
  kek_version integer NOT NULL,
  status text NOT NULL DEFAULT 'ok' CHECK (status IN ('ok','failing','provider_outage')),
  status_since timestamptz NOT NULL DEFAULT now(),
  models jsonb NOT NULL,
  monthly_credit_ceiling numeric,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE explanations (
  id uuid PRIMARY KEY,
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  check_id text NOT NULL,
  evidence_hash text NOT NULL,
  provider text NOT NULL CHECK (provider IN ('anthropic','openai')),
  model text NOT NULL,
  text text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organisation_id, check_id, evidence_hash)
);
CREATE TABLE ai_usage (
  id uuid PRIMARY KEY,
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  member_id uuid,
  purpose text NOT NULL CHECK (purpose IN ('explain','chat')),
  provider text NOT NULL CHECK (provider IN ('anthropic','openai')),
  model text NOT NULL,
  key_source text NOT NULL CHECK (key_source IN ('opsagent','byok')),
  input_tokens bigint NOT NULL,
  output_tokens bigint NOT NULL,
  cache_read_tokens bigint NOT NULL,
  cache_write_tokens bigint NOT NULL,
  credits numeric NOT NULL,
  estimated boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ai_usage_org_created_idx ON ai_usage (organisation_id, created_at);
CREATE TABLE ai_credit_grants (
  id uuid PRIMARY KEY,
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  credits numeric NOT NULL,
  source text NOT NULL DEFAULT 'topup' CHECK (source IN ('topup')),
  stripe_event_id text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE ai_notices (
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  key text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organisation_id, key)
);
CREATE TABLE chat_sessions (
  id uuid PRIMARY KEY,
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  member_id uuid NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  title text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_message_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX chat_sessions_member_idx
  ON chat_sessions (organisation_id, member_id, last_message_at DESC);
CREATE INDEX chat_sessions_last_message_idx ON chat_sessions (last_message_at);
CREATE TABLE chat_messages (
  id uuid PRIMARY KEY,
  session_id uuid NOT NULL REFERENCES chat_sessions(id) ON DELETE CASCADE,
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  role text NOT NULL CHECK (role IN ('user','assistant')),
  content jsonb NOT NULL,
  partial boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX chat_messages_session_idx ON chat_messages (session_id, created_at);
"#;

const DOWN: &str = r#"
DROP TABLE chat_messages;
DROP TABLE chat_sessions;
DROP TABLE ai_notices;
DROP TABLE ai_credit_grants;
DROP TABLE ai_usage;
DROP TABLE explanations;
DROP TABLE model_keys;
ALTER TABLE findings DROP COLUMN evidence_hash;
ALTER TABLE organisations DROP COLUMN ai_enabled, DROP COLUMN ai_topup_balance;
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
