use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// Daily Cost Explorer spend per service for the Spend page; one row per (connection, day,
// service), upserted by the nightly full scan, expired 90 days after `day`.
const UP: &str = "CREATE TABLE cost_daily (
  organisation_id uuid NOT NULL REFERENCES organisations(id),
  connection_id uuid NOT NULL REFERENCES connections(id),
  day date NOT NULL,
  service text NOT NULL,
  amount_usd numeric(14,4) NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (connection_id, day, service));
CREATE INDEX cost_daily_org_conn_day_idx ON cost_daily (organisation_id, connection_id, day);";

const DOWN: &str = "DROP TABLE cost_daily;";

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
