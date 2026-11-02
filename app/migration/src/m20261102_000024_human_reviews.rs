use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// human-review.md, Data: no FKs but the organisation; the row keeps the text captured at request
// time (`target_label`, `requester_email`) and the price then.
const UP: &str = r#"
CREATE TABLE human_review_requests (
  id uuid PRIMARY KEY,
  organisation_id uuid NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
  kind text NOT NULL CHECK (kind IN ('finding','account')),
  finding_id uuid,
  connection_id uuid,
  target_label text NOT NULL,
  note text CHECK (char_length(note) <= 2000),
  price_cents integer NOT NULL,
  requested_by uuid NOT NULL,
  requester_email text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((kind = 'finding' AND finding_id IS NOT NULL) OR (kind = 'account' AND connection_id IS NOT NULL))
);
CREATE INDEX human_review_requests_org_created_idx
  ON human_review_requests (organisation_id, created_at DESC);
"#;

const DOWN: &str = "DROP TABLE human_review_requests;";

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
