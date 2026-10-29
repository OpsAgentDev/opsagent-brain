use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// billing.md: the organisation's billing state (webhooks write it), webhook idempotency, and
// when a connection was disconnected (billable to the end of that period).
const UP: &str = r#"
ALTER TABLE organisations
  ADD COLUMN stripe_subscription_id text,
  ADD COLUMN billing_status text NOT NULL DEFAULT 'none' CHECK (billing_status IN
    ('none','trialing','active','past_due','paused','canceled','trial_ended')),
  ADD COLUMN billing_tier text CHECK (billing_tier IN ('starter','team','scale')),
  ADD COLUMN billing_quantity integer,
  ADD COLUMN trial_ends_at timestamptz,
  ADD COLUMN current_period_start timestamptz,
  ADD COLUMN current_period_end timestamptz,
  ADD COLUMN past_due_since timestamptz,
  ADD COLUMN billing_event_at timestamptz,
  ADD COLUMN payment_event_at timestamptz;
CREATE UNIQUE INDEX organisations_stripe_customer_idx ON organisations (stripe_customer_id)
  WHERE stripe_customer_id IS NOT NULL;
CREATE TABLE stripe_events (
  id text PRIMARY KEY,
  type text NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE connections ADD COLUMN disconnected_at timestamptz;
UPDATE connections SET disconnected_at = updated_at WHERE status = 'disconnected';
"#;

const DOWN: &str = r#"
ALTER TABLE connections DROP COLUMN disconnected_at;
DROP TABLE stripe_events;
DROP INDEX organisations_stripe_customer_idx;
ALTER TABLE organisations
  DROP COLUMN stripe_subscription_id, DROP COLUMN billing_status, DROP COLUMN billing_tier,
  DROP COLUMN billing_quantity, DROP COLUMN trial_ends_at, DROP COLUMN current_period_start,
  DROP COLUMN current_period_end, DROP COLUMN past_due_since, DROP COLUMN billing_event_at,
  DROP COLUMN payment_event_at;
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
