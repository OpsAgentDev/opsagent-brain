use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// ai-connections.md, Data: a key has a slot and an optional custom base URL, the credit ceiling
// moves to the organisation, and a usage row records the slot and endpoint host that served it.
const UP: &str = r#"
ALTER TABLE model_keys ADD COLUMN slot text NOT NULL DEFAULT 'primary' CHECK (slot IN ('primary','backup')),
  ADD COLUMN base_url text;
ALTER TABLE model_keys DROP CONSTRAINT model_keys_organisation_id_key;
ALTER TABLE model_keys ADD CONSTRAINT model_keys_org_slot_key UNIQUE (organisation_id, slot);
ALTER TABLE organisations ADD COLUMN ai_monthly_credit_ceiling numeric;
UPDATE organisations o SET ai_monthly_credit_ceiling = k.monthly_credit_ceiling
  FROM model_keys k WHERE k.organisation_id = o.id;
ALTER TABLE model_keys DROP COLUMN monthly_credit_ceiling;
ALTER TABLE ai_usage ADD COLUMN slot text CHECK (slot IN ('primary','backup')), ADD COLUMN base_host text;
"#;

const DOWN: &str = r#"
ALTER TABLE ai_usage DROP COLUMN slot, DROP COLUMN base_host;
DELETE FROM model_keys WHERE slot = 'backup';
ALTER TABLE model_keys ADD COLUMN monthly_credit_ceiling numeric;
UPDATE model_keys k SET monthly_credit_ceiling = o.ai_monthly_credit_ceiling
  FROM organisations o WHERE o.id = k.organisation_id;
ALTER TABLE organisations DROP COLUMN ai_monthly_credit_ceiling;
ALTER TABLE model_keys DROP CONSTRAINT model_keys_org_slot_key;
ALTER TABLE model_keys ADD CONSTRAINT model_keys_organisation_id_key UNIQUE (organisation_id);
ALTER TABLE model_keys DROP COLUMN slot, DROP COLUMN base_url;
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
