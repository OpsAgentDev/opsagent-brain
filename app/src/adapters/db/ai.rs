//! `AiRepo` on Postgres: the AI switch and top-up balance on `organisations`, BYOK keys,
//! metering, cached explanations and once-only notices.
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    ai::{AiRepo, Explanation, KeySource, KeyStatus, ModelKey, NewModelKey, RoleModels, UsageRow},
    model::AiProvider,
    repo::{RepoError, RepoResult},
};
use sea_orm::{prelude::Decimal, ConnectionTrait, QueryResult, Value};
use uuid::Uuid;

use super::ledger_storage::stmt;
use super::{db_err, Conn, Pg};

const KEY_COLS: &str = "id, organisation_id, provider, last4, status, status_since, models, \
  monthly_credit_ceiling, ciphertext, nonce, kek_version";

/// A new id each time: notices keyed on the old key's id do not carry over.
const PUT_KEY: &str = "INSERT INTO model_keys (id, organisation_id, provider, last4, ciphertext, \
  nonce, kek_version, models, monthly_credit_ceiling) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
  ON CONFLICT (organisation_id) DO UPDATE SET id = EXCLUDED.id, provider = EXCLUDED.provider, \
  last4 = EXCLUDED.last4, ciphertext = EXCLUDED.ciphertext, nonce = EXCLUDED.nonce, \
  kek_version = EXCLUDED.kek_version, models = EXCLUDED.models, \
  monthly_credit_ceiling = EXCLUDED.monthly_credit_ceiling, status = 'ok', status_since = now(), \
  created_at = now(), updated_at = now() RETURNING ";

/// One statement, so the row and the debit commit together.
const USAGE: &str = "WITH u AS (INSERT INTO ai_usage (id, organisation_id, member_id, purpose, \
  provider, model, key_source, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, \
  credits, estimated) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)) \
  UPDATE organisations SET ai_topup_balance = GREATEST(ai_topup_balance - $14, 0) WHERE id = $2";

const GRANT: &str = "WITH g AS (INSERT INTO ai_credit_grants (id, organisation_id, credits, \
  stripe_event_id) VALUES ($1, $2, $3, $4) ON CONFLICT (stripe_event_id) DO NOTHING \
  RETURNING credits) UPDATE organisations SET ai_topup_balance = ai_topup_balance + g.credits, \
  updated_at = now() FROM g WHERE organisations.id = $2";

const EXPLANATION: &str = "SELECT check_id, evidence_hash, provider, model, text, created_at \
  FROM explanations WHERE organisation_id = $1 AND check_id = $2 AND evidence_hash = $3";

fn get<T: sea_orm::TryGetable>(r: &QueryResult, col: &str) -> RepoResult<T> {
    r.try_get("", col).map_err(db_err)
}

fn provider(r: &QueryResult) -> RepoResult<AiProvider> {
    let s: String = get(r, "provider")?;
    AiProvider::parse(&s).ok_or_else(|| RepoError::Storage(format!("unknown provider {s:?}")))
}

fn key_of(r: &QueryResult) -> RepoResult<ModelKey> {
    let status: String = get(r, "status")?;
    let models: serde_json::Value = get(r, "models")?;
    Ok(ModelKey {
        id: get(r, "id")?,
        organisation_id: get(r, "organisation_id")?,
        provider: provider(r)?,
        last4: get(r, "last4")?,
        status: KeyStatus::parse(&status)
            .ok_or_else(|| RepoError::Storage(format!("unknown key status {status:?}")))?,
        status_since: get(r, "status_since")?,
        models: serde_json::from_value(models).map_err(db_err)?,
        monthly_credit_ceiling: get(r, "monthly_credit_ceiling")?,
        ciphertext: get(r, "ciphertext")?,
        nonce: get(r, "nonce")?,
        kek_version: get(r, "kek_version")?,
    })
}

fn explanation_of(r: &QueryResult) -> RepoResult<Explanation> {
    Ok(Explanation {
        check_id: get(r, "check_id")?,
        evidence_hash: get(r, "evidence_hash")?,
        provider: provider(r)?,
        model: get(r, "model")?,
        text: get(r, "text")?,
        created_at: get(r, "created_at")?,
    })
}

fn models_json(m: &RoleModels) -> RepoResult<Value> {
    Ok(serde_json::to_value(m).map_err(db_err)?.into())
}

impl<C: Conn> Pg<C> {
    pub(super) async fn query_row(
        &self,
        sql: &str,
        values: Vec<Value>,
    ) -> RepoResult<Option<QueryResult>> {
        self.db()
            .query_one_raw(stmt(sql, values))
            .await
            .map_err(db_err)
    }

    pub(super) async fn rows_changed(&self, sql: &str, values: Vec<Value>) -> RepoResult<u64> {
        let r = self.db().execute_raw(stmt(sql, values)).await;
        Ok(r.map_err(db_err)?.rows_affected())
    }

    /// A column of the organisation's row; `NotFound` for an unknown organisation.
    async fn org_column<T: sea_orm::TryGetable>(&self, org: Uuid, col: &str) -> RepoResult<T> {
        let sql = format!("SELECT {col} FROM organisations WHERE id = $1");
        let r = self.query_row(&sql, vec![org.into()]).await?;
        get(&r.ok_or(RepoError::NotFound)?, col)
    }
}

#[async_trait]
impl<C: Conn> AiRepo for Pg<C> {
    async fn enabled(&self, organisation_id: Uuid) -> RepoResult<bool> {
        self.org_column(organisation_id, "ai_enabled").await
    }

    async fn set_enabled(&self, organisation_id: Uuid, on: bool) -> RepoResult<()> {
        let sql = "UPDATE organisations SET ai_enabled = $2, updated_at = now() WHERE id = $1";
        match self
            .rows_changed(sql, vec![organisation_id.into(), on.into()])
            .await?
        {
            0 => Err(RepoError::NotFound),
            _ => Ok(()),
        }
    }

    async fn key(&self, organisation_id: Uuid) -> RepoResult<Option<ModelKey>> {
        let sql = format!("SELECT {KEY_COLS} FROM model_keys WHERE organisation_id = $1");
        let r = self.query_row(&sql, vec![organisation_id.into()]).await?;
        r.as_ref().map(key_of).transpose()
    }

    async fn put_key(&self, organisation_id: Uuid, k: &NewModelKey) -> RepoResult<ModelKey> {
        let values = vec![
            Uuid::now_v7().into(),
            organisation_id.into(),
            k.provider.as_str().into(),
            k.last4.clone().into(),
            k.ciphertext.clone().into(),
            k.nonce.clone().into(),
            k.kek_version.into(),
            models_json(&k.models)?,
            k.monthly_credit_ceiling.into(),
        ];
        let r = self
            .query_row(&format!("{PUT_KEY}{KEY_COLS}"), values)
            .await?;
        key_of(&r.ok_or_else(|| db_err("upsert returned no row"))?)
    }

    async fn update_key(
        &self,
        organisation_id: Uuid,
        models: &RoleModels,
        ceiling: Option<Decimal>,
    ) -> RepoResult<bool> {
        let sql = "UPDATE model_keys SET models = $2, monthly_credit_ceiling = $3, \
                   updated_at = now() WHERE organisation_id = $1";
        let values = vec![organisation_id.into(), models_json(models)?, ceiling.into()];
        Ok(self.rows_changed(sql, values).await? == 1)
    }

    async fn delete_key(&self, organisation_id: Uuid) -> RepoResult<bool> {
        let sql = "DELETE FROM model_keys WHERE organisation_id = $1";
        Ok(self.rows_changed(sql, vec![organisation_id.into()]).await? == 1)
    }

    async fn set_key_status(
        &self,
        organisation_id: Uuid,
        key_id: Uuid,
        status: KeyStatus,
        at: DateTime<Utc>,
    ) -> RepoResult<bool> {
        let sql = "UPDATE model_keys SET status = $3, status_since = $4, updated_at = now() \
                   WHERE organisation_id = $1 AND id = $2 AND status <> $3";
        let values = vec![
            organisation_id.into(),
            key_id.into(),
            status.as_str().into(),
            at.into(),
        ];
        Ok(self.rows_changed(sql, values).await? == 1)
    }

    async fn record_usage(&self, row: &UsageRow, topup_debit: Decimal) -> RepoResult<()> {
        let u = &row.usage;
        let values = vec![
            Uuid::now_v7().into(),
            row.organisation_id.into(),
            row.member_id.into(),
            row.purpose.as_str().into(),
            row.provider.as_str().into(),
            row.model.clone().into(),
            row.key_source.as_str().into(),
            (u.input_tokens as i64).into(),
            (u.output_tokens as i64).into(),
            (u.cache_read_tokens as i64).into(),
            (u.cache_write_tokens as i64).into(),
            row.credits.into(),
            row.estimated.into(),
            topup_debit.into(),
        ];
        self.rows_changed(USAGE, values).await.map(|_| ())
    }

    async fn credits_used(
        &self,
        organisation_id: Uuid,
        source: KeySource,
        since: DateTime<Utc>,
        until: DateTime<Utc>,
    ) -> RepoResult<Decimal> {
        let sql = "SELECT coalesce(sum(credits), 0) AS n FROM ai_usage WHERE organisation_id = $1 \
                   AND key_source = $2 AND created_at >= $3 AND created_at < $4";
        let values = vec![
            organisation_id.into(),
            source.as_str().into(),
            since.into(),
            until.into(),
        ];
        let r = self.query_row(sql, values).await?;
        get(&r.ok_or_else(|| db_err("sum returned no row"))?, "n")
    }

    async fn topup_balance(&self, organisation_id: Uuid) -> RepoResult<Decimal> {
        self.org_column(organisation_id, "ai_topup_balance").await
    }

    async fn grant_topup(
        &self,
        organisation_id: Uuid,
        credits: Decimal,
        stripe_event_id: &str,
    ) -> RepoResult<bool> {
        let values = vec![
            Uuid::now_v7().into(),
            organisation_id.into(),
            credits.into(),
            stripe_event_id.into(),
        ];
        Ok(self.rows_changed(GRANT, values).await? == 1)
    }

    async fn explanation(
        &self,
        organisation_id: Uuid,
        check_id: &str,
        hash: &str,
    ) -> RepoResult<Option<Explanation>> {
        let values = vec![organisation_id.into(), check_id.into(), hash.into()];
        let r = self.query_row(EXPLANATION, values).await?;
        r.as_ref().map(explanation_of).transpose()
    }

    async fn put_explanation(
        &self,
        organisation_id: Uuid,
        e: &Explanation,
    ) -> RepoResult<Explanation> {
        // Two statements: the read sees a row a concurrent insert committed while this one waited.
        let sql =
            "INSERT INTO explanations (id, organisation_id, check_id, evidence_hash, provider, \
                   model, text, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                   ON CONFLICT (organisation_id, check_id, evidence_hash) DO NOTHING";
        let values = vec![
            Uuid::now_v7().into(),
            organisation_id.into(),
            e.check_id.clone().into(),
            e.evidence_hash.clone().into(),
            e.provider.as_str().into(),
            e.model.clone().into(),
            e.text.clone().into(),
            e.created_at.into(),
        ];
        self.rows_changed(sql, values).await?;
        self.explanation(organisation_id, &e.check_id, &e.evidence_hash)
            .await?
            .ok_or_else(|| db_err("explanation missing after insert"))
    }

    async fn notice_once(&self, organisation_id: Uuid, key: &str) -> RepoResult<bool> {
        let sql = "INSERT INTO ai_notices (organisation_id, key) VALUES ($1, $2) \
                   ON CONFLICT DO NOTHING";
        Ok(self
            .rows_changed(sql, vec![organisation_id.into(), key.into()])
            .await?
            == 1)
    }
}
