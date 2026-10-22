use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

const UP: &str = r#"CREATE TABLE audit_events (
  id uuid PRIMARY KEY, organisation_id uuid,
  actor_type text NOT NULL CHECK (actor_type IN ('member','system','mcp_client','staff')),
  actor_id text, action text NOT NULL, target_type text, target_id text, outcome text,
  metadata jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX audit_events_organisation_id_idx ON audit_events (organisation_id);
CREATE OR REPLACE FUNCTION audit_events_immutable() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
  RAISE EXCEPTION 'audit_events is insert-only';
END;
$fn$;
CREATE TRIGGER audit_events_immutable BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION audit_events_immutable();"#;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection().execute_unprepared(UP).await.map(|_| ())
    }

    async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.get_connection().execute_unprepared("DROP TRIGGER IF EXISTS audit_events_immutable ON audit_events; DROP FUNCTION IF EXISTS audit_events_immutable(); DROP TABLE IF EXISTS audit_events").await.map(|_| ())
    }
}
