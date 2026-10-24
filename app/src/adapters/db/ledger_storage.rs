//! Postgres `ledger::Storage`. Fenced writes are raw SQL so the fence check and the write are one statement.
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::run::{RunKey, RunStatus};
use opsagent_ledger::{
    Checkpoint, CreateRunOutcome, EffectState, LedgerError, Result, RunRow, Storage,
};
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, QueryResult, Statement, Value};
use uuid::Uuid;

use super::{Conn, Pg};
use crate::models::{enum_of, enum_str};

/// `Pg` is the ledger storage: bound to the pool by default, or to a transaction to commit run
/// writes with other work.
pub type PgStorage<C = DatabaseConnection> = Pg<C>;

impl<C: Conn> Pg<C> {
    async fn one(&self, sql: &str, values: Vec<Value>) -> Result<Option<QueryResult>> {
        self.db()
            .query_one_raw(stmt(sql, values))
            .await
            .map_err(db_err)
    }

    /// Rows affected; 0 means the fence (or the id) did not match.
    async fn exec(&self, sql: &str, values: Vec<Value>) -> Result<u64> {
        self.db()
            .execute_raw(stmt(sql, values))
            .await
            .map(|r| r.rows_affected())
            .map_err(db_err)
    }
}

pub fn stmt(sql: &str, values: Vec<Value>) -> Statement {
    Statement::from_sql_and_values(DbBackend::Postgres, sql, values)
}

pub fn db_err(e: impl std::fmt::Display) -> LedgerError {
    LedgerError::Storage(e.to_string())
}

/// Locks the run row inside `txn` if `fence` is still current, so a stale worker's
/// transaction cannot commit domain writes. `Err(StaleFence)` otherwise.
pub async fn hold_fence(txn: &impl ConnectionTrait, run_id: Uuid, fence: u64) -> Result<()> {
    txn.query_one_raw(stmt(
        // tenancy: the ledger addresses runs by id (from the queue); the row names its organisation.
        "SELECT 1 FROM runs WHERE id = $1 AND fence = $2 FOR UPDATE",
        vec![run_id.into(), (fence as i64).into()],
    ))
    .await
    .map_err(db_err)?
    .map(|_| ())
    .ok_or(LedgerError::StaleFence)
}

const COLS: &str = "id, organisation_id, connection_id, job_type, scheduled_at, status, checkpoint, fence, attempts, partial_reason";

fn row(r: &QueryResult) -> Result<RunRow> {
    let status: String = r.try_get("", "status").map_err(db_err)?;
    let checkpoint: serde_json::Value = r.try_get("", "checkpoint").map_err(db_err)?;
    let scheduled_at: DateTime<Utc> = r.try_get("", "scheduled_at").map_err(db_err)?;
    let fence: i64 = r.try_get("", "fence").map_err(db_err)?;
    let attempts: i32 = r.try_get("", "attempts").map_err(db_err)?;
    Ok(RunRow {
        id: r.try_get("", "id").map_err(db_err)?,
        key: RunKey {
            organisation_id: r.try_get("", "organisation_id").map_err(db_err)?,
            connection_id: r.try_get("", "connection_id").map_err(db_err)?,
            job_type: r.try_get("", "job_type").map_err(db_err)?,
            scheduled_at,
        },
        status: enum_of(&status).ok_or_else(|| db_err(format!("bad run status: {status}")))?,
        checkpoint: serde_json::from_value(checkpoint).map_err(db_err)?,
        fence: u64::try_from(fence).map_err(db_err)?,
        attempts: u32::try_from(attempts).map_err(db_err)?,
        partial_reason: r.try_get("", "partial_reason").map_err(db_err)?,
    })
}

fn cp_json(cp: &Checkpoint) -> Result<serde_json::Value> {
    serde_json::to_value(cp).map_err(db_err)
}

#[async_trait]
impl<C: Conn> Storage for Pg<C> {
    async fn create_run(&self, key: RunKey) -> Result<CreateRunOutcome> {
        let k = || {
            vec![
                key.organisation_id.into(),
                key.connection_id.into(),
                key.job_type.clone().into(),
                key.scheduled_at.into(),
            ]
        };
        let mut v = k();
        v.push(Uuid::now_v7().into());
        v.push(cp_json(&Checkpoint::default())?.into());
        let created = self
            .exec(
            "INSERT INTO runs (organisation_id, connection_id, job_type, scheduled_at, id, checkpoint) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (organisation_id, connection_id, job_type, scheduled_at) DO NOTHING",
            v,
        )
        .await?
            == 1;
        let sql = format!(
            "SELECT {COLS} FROM runs WHERE organisation_id IS NOT DISTINCT FROM $1 \
             AND connection_id IS NOT DISTINCT FROM $2 AND job_type = $3 AND scheduled_at = $4"
        );
        let run = row(&self.one(&sql, k()).await?.ok_or(LedgerError::NotFound)?)?;
        Ok(CreateRunOutcome { run, created })
    }

    async fn load_run(&self, id: Uuid) -> Result<RunRow> {
        // tenancy: the ledger addresses runs by id (from the queue); the row names its organisation.
        let sql = format!("SELECT {COLS} FROM runs WHERE id = $1");
        row(&self
            .one(&sql, vec![id.into()])
            .await?
            .ok_or(LedgerError::NotFound)?)
    }

    async fn hold_fence(&self, id: Uuid, fence: u64) -> Result<()> {
        hold_fence(self.db(), id, fence).await
    }

    async fn bump_fence(&self, id: Uuid) -> Result<u64> {
        let r = self
            .one(
                // tenancy: the ledger addresses runs by id (from the queue); the row names its organisation.
                "UPDATE runs SET fence = fence + 1, updated_at = now() WHERE id = $1 RETURNING fence",
                vec![id.into()],
            )
            .await?
            .ok_or(LedgerError::NotFound)?;
        let f: i64 = r.try_get("", "fence").map_err(db_err)?;
        u64::try_from(f).map_err(db_err)
    }

    async fn write_checkpoint(&self, id: Uuid, fence: u64, cp: &Checkpoint) -> Result<()> {
        let n = self
            .exec(
                // tenancy: the ledger addresses runs by id (from the queue); the row names its organisation.
                "UPDATE runs SET checkpoint = $3, updated_at = now() WHERE id = $1 AND fence = $2",
                vec![id.into(), (fence as i64).into(), cp_json(cp)?.into()],
            )
            .await?;
        if n == 0 {
            return Err(LedgerError::StaleFence);
        }
        Ok(())
    }

    async fn set_status(
        &self,
        id: Uuid,
        fence: u64,
        status: RunStatus,
        partial_reason: Option<String>,
    ) -> Result<()> {
        let n = self
            .exec(
                // tenancy: the ledger addresses runs by id (from the queue); the row names its organisation.
                "UPDATE runs SET status = $3, partial_reason = $4, updated_at = now(), \
                 started_at = CASE WHEN $3 = 'running' THEN coalesce(started_at, now()) ELSE started_at END, \
                 finished_at = CASE WHEN $3 IN ('done','failed','partial','skipped') THEN now() ELSE NULL END \
                 WHERE id = $1 AND fence = $2",
                vec![
                    id.into(),
                    (fence as i64).into(),
                    enum_str(status).into(),
                    partial_reason.into(),
                ],
            )
            .await?;
        if n == 0 {
            return Err(LedgerError::StaleFence);
        }
        Ok(())
    }

    async fn skip_run(&self, id: Uuid, reason: &str) -> Result<bool> {
        let n = self
            .exec(
                // tenancy: the ledger addresses runs by id (from the queue); the row names its organisation.
                "UPDATE runs SET status = 'skipped', partial_reason = $2, fence = fence + 1, \
                 next_attempt_at = NULL, finished_at = now(), updated_at = now() \
                 WHERE id = $1 AND status = 'queued'",
                vec![id.into(), reason.into()],
            )
            .await?;
        Ok(n == 1)
    }

    async fn effect_begin(&self, run_id: Uuid, key: &str) -> Result<EffectState> {
        let inserted = self
            .exec(
                "INSERT INTO side_effects (id, run_id, effect_key, status, started_at) \
                 VALUES ($1, $2, $3, 'started', now()) ON CONFLICT (run_id, effect_key) DO NOTHING",
                vec![Uuid::now_v7().into(), run_id.into(), key.into()],
            )
            .await?;
        if inserted == 1 {
            return Ok(EffectState::New);
        }
        let r = self
            .one(
                "SELECT status, external_ref FROM side_effects WHERE run_id = $1 AND effect_key = $2",
                vec![run_id.into(), key.into()],
            )
            .await?
            .ok_or(LedgerError::NotFound)?;
        let status: String = r.try_get("", "status").map_err(db_err)?;
        Ok(if status == "done" {
            EffectState::Done(r.try_get("", "external_ref").map_err(db_err)?)
        } else {
            EffectState::Started
        })
    }

    async fn effect_done(
        &self,
        run_id: Uuid,
        key: &str,
        external_ref: Option<String>,
    ) -> Result<()> {
        self.exec(
            "INSERT INTO side_effects (id, run_id, effect_key, status, external_ref, done_at) \
             VALUES ($1, $2, $3, 'done', $4, now()) ON CONFLICT (run_id, effect_key) \
             DO UPDATE SET status = 'done', external_ref = EXCLUDED.external_ref, done_at = now(), updated_at = now()",
            vec![Uuid::now_v7().into(), run_id.into(), key.into(), external_ref.into()],
        )
        .await
        .map(|_| ())
    }

    async fn clear_enqueue_marker(&self, id: Uuid, marker_at: DateTime<Utc>) -> Result<bool> {
        let n = self
            .exec(
                // tenancy: the ledger addresses runs by id (from the queue); the row names its organisation.
                "UPDATE runs SET next_attempt_at = NULL, updated_at = now() WHERE id = $1 AND next_attempt_at = $2",
                vec![id.into(), marker_at.into()],
            )
            .await?;
        Ok(n == 1)
    }

    async fn schedule_retry(&self, id: Uuid, attempts: u32, next_at: DateTime<Utc>) -> Result<()> {
        let n = self
            .exec(
                // tenancy: the ledger addresses runs by id (from the queue); the row names its organisation.
                "UPDATE runs SET attempts = $2, next_attempt_at = $3, status = 'queued', updated_at = now() WHERE id = $1",
                vec![id.into(), (attempts as i32).into(), next_at.into()],
            )
            .await?;
        if n == 0 {
            return Err(LedgerError::NotFound);
        }
        Ok(())
    }
}
