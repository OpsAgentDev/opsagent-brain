//! `VerifyConnection`: assume the customer role, diff the policy, set the connection status
//! (PRD 7.2). The run is worked under a fenced lease; every run ends: an unexpected error is
//! retried on the ledger schedule, then fails.
use std::{sync::Arc, time::Duration};

use opsagent_connectors::{
    registry as providers, CallContext, Connector, ConnectorError, Credentials, VerifyOutcome,
};
use opsagent_core::{
    connection::{Connection, ConnectionStatus as S},
    repo::Clock,
    run::RunStatus,
};
use opsagent_ledger::{
    lease, redis,
    retry::{retry_or_fail, settle},
    LedgerError, RunRow,
};
use opsagent_secrets::Kek;
use uuid::Uuid;

use super::{
    classify::{classify, lerr, LResult},
    RunDispatcher,
};
use crate::{
    actions::{billing::BillingGate, uow::UnitOfWork, ConnectorSource},
    creds,
    error::AppResult,
};

const LEASE_TTL: Duration = Duration::from_secs(120);

#[derive(Clone)]
pub struct VerifyConnection {
    pub(super) uow: Arc<dyn UnitOfWork>,
    ledger_redis: redis::Client,
    kek: Arc<dyn Kek>,
    connectors: Arc<dyn ConnectorSource>,
    pub(super) dispatcher: Arc<RunDispatcher>,
    pub(super) clock: Arc<dyn Clock>,
    pub(super) gate: BillingGate,
}

/// Serves every provider with one connector.
struct Fixed(Arc<dyn Connector>);

impl ConnectorSource for Fixed {
    fn connector(&self, _provider: &str) -> Result<Arc<dyn Connector>, ConnectorError> {
        Ok(self.0.clone())
    }
}

type Called = Result<(VerifyOutcome, Credentials), ConnectorError>;

/// The run being worked on, under the lease at `fence`, and its connection as read at start.
pub(super) struct Step<'a> {
    pub run: &'a RunRow,
    pub fence: u64,
    pub c: &'a Connection,
}

impl VerifyConnection {
    pub fn new(
        uow: Arc<dyn UnitOfWork>,
        ledger_redis: redis::Client,
        kek: Arc<dyn Kek>,
        connectors: Arc<dyn ConnectorSource>,
        dispatcher: Arc<RunDispatcher>,
        clock: Arc<dyn Clock>,
        gate: BillingGate,
    ) -> Self {
        Self {
            uow,
            ledger_redis,
            kek,
            connectors,
            dispatcher,
            clock,
            gate,
        }
    }

    /// The same action calling `k` for every provider (tests).
    pub fn with_connector(self, k: Arc<dyn Connector>) -> Self {
        Self {
            connectors: Arc::new(Fixed(k)),
            ..self
        }
    }

    /// Runs (or re-runs) verify run `run_id`. A finished run, or one another worker holds,
    /// is left alone.
    pub async fn run(&self, run_id: Uuid) -> AppResult<()> {
        let storage = self.uow.ledger();
        let run = storage.load_run(run_id).await?;
        if matches!(
            run.status,
            RunStatus::Done | RunStatus::Failed | RunStatus::Skipped
        ) {
            return Ok(()); // Duplicate delivery of a finished run.
        }
        let worker = format!("verify-{}", Uuid::new_v4());
        let redis = &self.ledger_redis;
        let lease = match lease::acquire(storage, redis, run.id, &worker, LEASE_TTL).await {
            Ok(Some(l)) => l,
            Ok(None) | Err(LedgerError::LeaseHeld) => return Ok(()), // another worker has it
            Err(e) => return Err(e.into()),
        };
        let res = match self.work(&run, lease.fence).await {
            Err(LedgerError::StaleFence) => Ok(()),
            Err(e) => settle(storage, run.id, run.attempts, lease.fence, &e)
                .await
                .map(|_| ()),
            ok => ok,
        };
        lease::release(redis, &lease).await;
        match res {
            Ok(()) | Err(LedgerError::StaleFence) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    async fn work(&self, run: &RunRow, fence: u64) -> LResult<()> {
        let storage = self.uow.ledger();
        storage
            .set_status(run.id, fence, RunStatus::Running, None)
            .await?;
        let key = &run.key;
        let (org, conn_id) = key
            .organisation_id
            .zip(key.connection_id)
            .ok_or(LedgerError::NotFound)?;
        let c = self.uow.connections().get(org, conn_id).await;
        let c = c.map_err(lerr)?.ok_or(LedgerError::NotFound)?;
        let skip = if self.uow.orgs().is_deleted(org).await.map_err(lerr)? {
            Some("organisation_deleted")
        } else {
            match c.status {
                S::Pending => Some("connection_pending"),
                S::Disconnected => Some("connection_disconnected"),
                _ => None,
            }
        };
        if let Some(reason) = skip {
            return storage
                .set_status(run.id, fence, RunStatus::Skipped, Some(reason.into()))
                .await;
        }
        let step = Step { run, fence, c: &c };
        match self.call(&c, run.id).await? {
            Ok((o, cr)) => self.conclude(&step, cr.account(), &o).await,
            Err(e) => self.connector_error(&step, &e).await,
        }
    }

    /// Decrypts the credentials and calls `verify`. Undecryptable credentials fail the run.
    async fn call(&self, c: &Connection, run_id: Uuid) -> LResult<Called> {
        let (org, kek) = (c.organisation_id, self.kek.as_ref());
        let creds =
            creds::load(&*self.uow, kek, org, c.id)
                .await
                .map_err(|_| LedgerError::Job {
                    code: "credentials_unavailable".into(),
                    retry: false,
                })?;
        let context = CallContext {
            organisation_id: org,
            run_id,
            trigger: "verify".into(),
        };
        let cr = match providers::credentials(&c.provider, &creds, context) {
            Ok(cr) => cr,
            Err(e) => return Ok(Err(e)),
        };
        let k = match self.connectors.connector(&c.provider) {
            Ok(k) => k,
            Err(e) => return Ok(Err(e)),
        };
        Ok(k.verify(&cr).await.map(|o| (o, cr)))
    }

    /// Throttling, 5xx and network: retry without changing state, until exhausted. Anything
    /// else (or exhausted retries) is recorded as a verify error.
    async fn connector_error(&self, step: &Step<'_>, e: &ConnectorError) -> LResult<()> {
        let (code, transient) = classify(e);
        let run = step.run;
        let service = &step.c.provider;
        tracing::warn!(run = %run.id, error_code = %code, service, transient, "verify: connector error");
        let storage = self.uow.ledger();
        if transient && retry_or_fail(storage, run.id, run.attempts, step.fence).await? {
            return Ok(());
        }
        self.fail(step, &code).await
    }
}
