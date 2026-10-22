use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

const UP: &str = r#"CREATE EXTENSION IF NOT EXISTS citext;
CREATE TABLE organisations (
  id uuid PRIMARY KEY, name text NOT NULL, slug text NOT NULL UNIQUE,
  timezone text NOT NULL DEFAULT 'UTC', plan text, stripe_customer_id text,
  kek_version integer, wrapped_dek bytea, deleted_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE users (
  id uuid PRIMARY KEY, email citext NOT NULL UNIQUE, name text, github_id text UNIQUE, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE members (
  id uuid PRIMARY KEY,
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  user_id uuid NOT NULL REFERENCES users(id),
  role text NOT NULL CHECK (role IN ('owner','member')), created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organisation_id, user_id));
CREATE TABLE invites (
  id uuid PRIMARY KEY,
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  email citext NOT NULL, role text NOT NULL CHECK (role IN ('owner','member')),
  token_hash text NOT NULL, expires_at timestamptz NOT NULL, status text NOT NULL DEFAULT 'pending', created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX invites_organisation_id_idx ON invites (organisation_id);
CREATE TABLE magic_links (
  id uuid PRIMARY KEY, user_id uuid REFERENCES users(id), email citext,
  token_hash text NOT NULL, expires_at timestamptz NOT NULL, used_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (user_id IS NOT NULL OR email IS NOT NULL));
CREATE TABLE sessions (
  id text PRIMARY KEY, data bytea NOT NULL, expiry_date timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());"#;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection().execute_unprepared(UP).await.map(|_| ())
    }

    async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection().execute_unprepared("DROP TABLE IF EXISTS sessions, magic_links, invites, members, users, organisations CASCADE").await.map(|_| ())
    }
}
