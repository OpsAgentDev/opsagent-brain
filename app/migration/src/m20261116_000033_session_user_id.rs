use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// Whose session a row is, so a person can end all of theirs ("sign out everywhere"). Null for an
// anonymous session. Existing rows are filled from their stored JSON, so sessions that began
// before this column are ended too.
const UP: &str = "ALTER TABLE sessions ADD COLUMN user_id uuid;
UPDATE sessions SET user_id = (convert_from(data, 'UTF8')::jsonb ->> 'user_id')::uuid
  WHERE convert_from(data, 'UTF8')::jsonb ? 'user_id';
CREATE INDEX sessions_user_id_idx ON sessions (user_id) WHERE user_id IS NOT NULL;";

const DOWN: &str = "DROP INDEX sessions_user_id_idx;
ALTER TABLE sessions DROP COLUMN user_id;";

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
