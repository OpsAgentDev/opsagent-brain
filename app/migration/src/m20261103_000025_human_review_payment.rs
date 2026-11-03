use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// human-review.md, Paid through Stripe Checkout: existing rows were invoiced.
const UP: &str = r#"
ALTER TABLE human_review_requests
  ADD COLUMN payment text NOT NULL DEFAULT 'invoice' CHECK (payment IN ('invoice','pending','paid')),
  ADD COLUMN paid_at timestamptz;
"#;

const DOWN: &str = "ALTER TABLE human_review_requests DROP COLUMN payment, DROP COLUMN paid_at;";

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
