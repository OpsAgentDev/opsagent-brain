//! `verify` job: assume the customer role, diff the policy, set the connection status (PRD 7.2).
mod outcome;
mod verdict;

use std::time::Duration;

use async_trait::async_trait;
use loco_rs::{app::AppContext, bgworker::BackgroundWorker, Result};
use opsagent_connectors::{
    registry as providers, CallContext, Connector, ConnectorError, Credentials, VerifyOutcome,
};
use opsagent_core::{connection::ConnectionStatus as S, run::RunStatus};
use opsagent_ledger::{
    lease,
    retry::{retry_or_fail, settle},
    LedgerError, RunRow, Storage,
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::common::{classify, err, lerr, redis_client, LResult};
use crate::{
    app::{kek, registry},
    models::{
        _entities::connections,
        connections::{load_creds, status_of},
        ledger_storage::PgStorage,
        organisations,
    },
};

const LEASE_TTL: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyArgs {
    pub run_id: Uuid,
}

pub struct VerifyWorker {
    ctx: AppContext,
}

#[async_trait]
impl BackgroundWorker<VerifyArgs> for VerifyWorker {
    fn build(ctx: &AppContext) -> Self {
        Self { ctx: ctx.clone() }
    }

    async fn perform(&self, args: VerifyArgs) -> Result<()> {
        verify(&self.ctx, args.run_id, None).await
    }
}

/// Runs (or re-runs) verify run `run_id` under a fenced lease, with connector `k` or the
/// registry's connector for the provider. Every run ends: an unexpected error is retried on
/// the ledger schedule, then fails.
pub async fn verify(ctx: &AppContext, run_id: Uuid, k: Option<&dyn Connector>) -> Result<()> {
    let storage = PgStorage::new(ctx.db.clone());
    let run = storage.load_run(run_id).await.map_err(err)?;
    if matches!(
        run.status,
        RunStatus::Done | RunStatus::Failed | RunStatus::Skipped
    ) {
        return Ok(()); // Duplicate delivery of a finished run.
    }
    let redis = redis_client(ctx)?;
    let worker = format!("verify-{}", Uuid::new_v4());
    let lease = match lease::acquire(&storage, &redis, run.id, &worker, LEASE_TTL).await {
        Ok(Some(l)) => l,
        Ok(None) | Err(LedgerError::LeaseHeld) => return Ok(()), // another worker has it
        Err(e) => return Err(err(e)),
    };
    let w = VerifyWorker { ctx: ctx.clone() };
    let res = match w.run(&storage, &run, lease.fence, k).await {
        Err(LedgerError::StaleFence) => Ok(()),
        Err(e) => settle(&storage, run.id, run.attempts, lease.fence, &e)
            .await
            .map(|_| ()),
        ok => ok,
    };
    lease::release(&redis, &lease).await;
    match res {
        Ok(()) | Err(LedgerError::StaleFence) => Ok(()),
        Err(e) => Err(err(e)),
    }
}

type Called = std::result::Result<(VerifyOutcome, Credentials), ConnectorError>;

/// The run being worked on, under the lease at `fence`, and its connection as read at start.
struct Step<'a> {
    run: &'a RunRow,
    fence: u64,
    c: &'a connections::Model,
}

impl VerifyWorker {
    async fn run(
        &self,
        storage: &PgStorage,
        run: &RunRow,
        fence: u64,
        k: Option<&dyn Connector>,
    ) -> LResult<()> {
        storage
            .set_status(run.id, fence, RunStatus::Running, None)
            .await?;
        let conn_id = run.key.connection_id.ok_or(LedgerError::NotFound)?;
        let c = connections::Entity::find_by_id(conn_id)
            .filter(connections::Column::OrganisationId.eq(run.key.organisation_id))
            .one(&self.ctx.db)
            .await
            .map_err(lerr)?
            .ok_or(LedgerError::NotFound)?;
        let status = status_of(&c).map_err(lerr)?;
        let skip = if organisations::deleted(&self.ctx.db, c.organisation_id)
            .await
            .map_err(lerr)?
        {
            Some("organisation_deleted".to_owned())
        } else if matches!(status, S::Pending | S::Disconnected) {
            Some(format!("connection_{}", c.status))
        } else {
            None
        };
        if let Some(reason) = skip {
            return storage
                .set_status(run.id, fence, RunStatus::Skipped, Some(reason))
                .await;
        }
        let step = Step { run, fence, c: &c };
        match self.call(&c, run.id, k).await? {
            Ok((o, cr)) => self.conclude(&step, status, cr.account(), &o).await,
            Err(e) => self.connector_error(storage, &step, &e).await,
        }
    }

    /// Decrypts the credentials and calls `verify`. Undecryptable credentials fail the run.
    async fn call(
        &self,
        c: &connections::Model,
        run_id: Uuid,
        k: Option<&dyn Connector>,
    ) -> LResult<Called> {
        let kek = kek(&self.ctx).map_err(lerr)?;
        let creds = load_creds(&self.ctx.db, kek.as_ref(), c)
            .await
            .map_err(|_| LedgerError::Job {
                code: "credentials_unavailable".into(),
                retry: false,
            })?;
        let context = CallContext {
            organisation_id: c.organisation_id,
            run_id,
            trigger: "verify".into(),
        };
        let cr = match providers::credentials(&c.provider, &creds, context) {
            Ok(cr) => cr,
            Err(e) => return Ok(Err(e)),
        };
        let owned;
        let k = match k {
            Some(k) => k,
            None => match registry(&self.ctx).map_err(lerr)?.connector(&c.provider) {
                Ok(b) => {
                    owned = b;
                    owned.as_ref()
                }
                Err(e) => return Ok(Err(e)),
            },
        };
        Ok(k.verify(&cr).await.map(|o| (o, cr)))
    }

    /// Throttling, 5xx and network: retry without changing state, until exhausted. Anything
    /// else (or exhausted retries) is recorded as a verify error.
    async fn connector_error(
        &self,
        storage: &PgStorage,
        step: &Step<'_>,
        e: &ConnectorError,
    ) -> LResult<()> {
        let (code, transient) = classify(e);
        let run = step.run;
        tracing::warn!(run = %run.id, code, transient, "verify: connector error");
        if transient && retry_or_fail(storage, run.id, run.attempts, step.fence).await? {
            return Ok(());
        }
        self.fail(step, &code).await
    }
}
