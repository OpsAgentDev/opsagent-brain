use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

const UP: &str = r#"
ALTER TABLE findings ADD COLUMN alerted_at timestamptz;
ALTER TABLE connections ADD COLUMN urgent_alerts boolean NOT NULL DEFAULT true;
"#;

const DOWN: &str = r#"
ALTER TABLE connections DROP COLUMN IF EXISTS urgent_alerts;
ALTER TABLE findings DROP COLUMN IF EXISTS alerted_at;
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
