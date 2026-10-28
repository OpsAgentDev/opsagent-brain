use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// Sign-in is user-scoped, deliberately not tenant-scoped: `passkeys` and the `users` columns
// carry no organisation_id (same exception as waitlist_entries and contact_messages).
const UP: &str = r#"
ALTER TABLE magic_links ADD COLUMN code_hash text, ADD COLUMN code_attempts int NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN google_id text UNIQUE;
CREATE TABLE passkeys (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users ON DELETE CASCADE,
  credential_id bytea NOT NULL UNIQUE,
  credential jsonb NOT NULL,
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz);
CREATE INDEX passkeys_user_id_idx ON passkeys (user_id);
"#;

const DOWN: &str = r#"
DROP TABLE IF EXISTS passkeys;
ALTER TABLE users DROP COLUMN IF EXISTS google_id;
ALTER TABLE magic_links DROP COLUMN IF EXISTS code_attempts, DROP COLUMN IF EXISTS code_hash;
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
