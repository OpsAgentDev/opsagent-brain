use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// The scopes a grant was approved for (mcp-contract.md, "Version 0.3"). Every grant made
// before this column stays read-only.
const UP: &str = "ALTER TABLE oauth_grants ADD COLUMN scope text NOT NULL DEFAULT 'opsagent.read'
  CHECK (scope IN ('opsagent.read','opsagent.read opsagent.write'));";

const DOWN: &str = "ALTER TABLE oauth_grants DROP COLUMN scope;";

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
