use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// OAuth for MCP clients (mcp-contract.md, "Data"). Clients and consent requests are global;
// grants and tokens carry organisation_id. No foreign key on member_id: removing a member
// deletes the member row, and the grant stays behind, revoked.
const UP: &str = r#"CREATE TABLE oauth_clients (
  client_id text PRIMARY KEY,
  kind text NOT NULL CHECK (kind IN ('dynamic','metadata_document')),
  name text NOT NULL,
  redirect_uris jsonb NOT NULL,
  document_fetched_at timestamptz,
  document_cache_until timestamptz,
  last_used_at timestamptz,
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE oauth_grants (
  id uuid PRIMARY KEY,
  client_id text NOT NULL REFERENCES oauth_clients(client_id),
  member_id uuid NOT NULL,
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  revoked_at timestamptz);
CREATE INDEX oauth_grants_org_member_idx ON oauth_grants (organisation_id, member_id);
CREATE INDEX oauth_grants_client_idx ON oauth_grants (client_id);
CREATE TABLE oauth_consent_requests (
  id uuid PRIMARY KEY,
  client_id text NOT NULL REFERENCES oauth_clients(client_id),
  redirect_uri text NOT NULL,
  code_challenge text NOT NULL,
  state text,
  resource text NOT NULL,
  scope text NOT NULL,
  member_id uuid,
  organisation_id uuid REFERENCES organisations(id),
  code_hash text,
  code_expires_at timestamptz,
  code_used_at timestamptz,
  grant_id uuid REFERENCES oauth_grants(id),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now());
CREATE UNIQUE INDEX oauth_consent_requests_code_hash_idx ON oauth_consent_requests (code_hash);
CREATE TABLE oauth_refresh_tokens (
  id uuid PRIMARY KEY,
  grant_id uuid NOT NULL REFERENCES oauth_grants(id),
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  token_hash text NOT NULL,
  expires_at timestamptz NOT NULL,
  spent_at timestamptz,
  successor_id uuid,
  created_at timestamptz NOT NULL DEFAULT now());
CREATE UNIQUE INDEX oauth_refresh_tokens_hash_idx ON oauth_refresh_tokens (token_hash);
CREATE INDEX oauth_refresh_tokens_grant_idx ON oauth_refresh_tokens (grant_id);
CREATE TABLE oauth_access_tokens (
  id uuid PRIMARY KEY,
  grant_id uuid NOT NULL REFERENCES oauth_grants(id),
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  token_hash text NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now());
CREATE UNIQUE INDEX oauth_access_tokens_hash_idx ON oauth_access_tokens (token_hash);
CREATE INDEX oauth_access_tokens_grant_idx ON oauth_access_tokens (grant_id);"#;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection().execute_unprepared(UP).await.map(|_| ())
    }

    async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection()
            .execute_unprepared(
                "DROP TABLE IF EXISTS oauth_access_tokens, oauth_refresh_tokens, \
                 oauth_consent_requests, oauth_grants, oauth_clients",
            )
            .await
            .map(|_| ())
    }
}
