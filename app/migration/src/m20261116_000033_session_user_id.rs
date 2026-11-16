use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// Whose session a row is, so a person can end all of theirs ("sign out everywhere"). Null for an
// anonymous session and for rows written before this column; the store fills it on the next save.
const UP: &str = "ALTER TABLE sessions ADD COLUMN user_id uuid;
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
