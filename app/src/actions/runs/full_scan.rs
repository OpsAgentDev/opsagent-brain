//! `full_scan` (PRD 7.3, jobs.md): one chunk per service × region, then a `finalize` chunk
//! that marks unseen resources gone, runs the checks and applies the finding lifecycle.
use std::{collections::BTreeSet, sync::Arc};

use opsagent_checks::Check;
use opsagent_connectors::{
    registry as providers, CallContext, Connector, Credentials, Registry, Scope,
};
use opsagent_core::{
    audit::AuditEntry,
    connection::{Connection, ConnectionStatus as S},
    repo::Clock,
    run::RunStatus,
};
use opsagent_ledger::{
    lease::{self, claim, unclaim},
    redis,
    retry::{fail_on_storage_error, settle},
    run_chunked, JobKind, LedgerError, Result, RunChunkedOptions, RunRow,
};
use opsagent_secrets::Kek;
use serde_json::json;
use uuid::Uuid;

use super::full_scan_chunks::{Scan, FINALIZE, SIMULATE};
use crate::{
    actions::uow::UnitOfWork,
    creds,
    models::enum_str,
    workers::common::{job_err, lerr, revoked},
};

pub(super) const JOB: JobKind = JobKind::FullScan;

/// Runs (or resumes) the scan of one run. Clone it to override the connector or the checks.
#[derive(Clone)]
pub struct FullScan {
    pub(super) uow: Arc<dyn UnitOfWork>,
    redis: redis::Client,
    kek: Arc<dyn Kek>,
    registry: Registry,
    pub(super) clock: Arc<dyn Clock>,
    connector: Option<Arc<dyn Connector>>,
    pub(super) checks: fn() -> Vec<Box<dyn Check>>,
}

/// How a run ends without (more) chunks.
enum End {
    Set(RunStatus, String),
    /// Retried or failed by `ledger::retry::settle`.
    Failed(LedgerError),
}

impl FullScan {
    pub fn new(
        uow: Arc<dyn UnitOfWork>,
        redis: redis::Client,
        kek: Arc<dyn Kek>,
        registry: Registry,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            uow,
            redis,
            kek,
            registry,
            clock,
            connector: None,
            checks: opsagent_checks::all,
        }
    }

    /// The scan with an explicit check set (tests inject faulty checks).
    pub fn with_checks(self, checks: fn() -> Vec<Box<dyn Check>>) -> Self {
        Self { checks, ..self }
    }

    /// The scan with connector `k` instead of the registry's (tests).
    pub fn with_connector(self, k: Arc<dyn Connector>) -> Self {
        Self {
            connector: Some(k),
            ..self
        }
    }

    /// Runs (or resumes) the scan for `run_id`; the run row must exist. A finished run is
    /// returned as is (duplicate delivery).
    pub async fn run(&self, run_id: Uuid, opts: RunChunkedOptions) -> Result<RunStatus> {
        let run = self.uow.ledger().load_run(run_id).await?;
        if !matches!(run.status, RunStatus::Queued | RunStatus::Running) {
            return Ok(run.status);
        }
        let c = self.connection(&run).await?;
        if self
            .uow
            .orgs()
            .is_deleted(c.organisation_id)
            .await
            .map_err(lerr)?
        {
            let skip = End::Set(RunStatus::Skipped, "organisation_deleted".into());
            return self.end(&run, &opts, skip).await;
        }
        if !matches!(c.status, S::Connected | S::Degraded) {
            let skip = End::Set(RunStatus::Skipped, format!("status:{}", enum_str(c.status)));
            return self.end(&run, &opts, skip).await;
        }
        // At most one full scan per connection (PRD 7.3); the run id owns the claim, so a
        // resumed run passes and any other run is skipped.
        let (key, owner) = (
            format!("lease:conn:{}:{}", c.id, JOB.as_str()),
            run_id.to_string(),
        );
        if !claim(&self.redis, &key, &owner, opts.time_cap + opts.lease_ttl).await? {
            let skip = End::Set(RunStatus::Skipped, "overlap".into());
            return self.end(&run, &opts, skip).await;
        }
        let res = self.claimed(&run, &c, opts).await;
        // A worker that took over this run's lease is still scanning: leave the claim to it.
        let status = self.uow.ledger().load_run(run_id).await.map(|r| r.status);
        if !matches!(status, Ok(RunStatus::Running)) {
            unclaim(&self.redis, &key, &owner).await;
        }
        res
    }

    /// The scan proper, once the connection is claimed: credentials, discovery, chunks.
    async fn claimed(
        &self,
        run: &RunRow,
        c: &Connection,
        opts: RunChunkedOptions,
    ) -> Result<RunStatus> {
        let k = match self.connector(c) {
            Ok(k) => k,
            Err(e) => return self.end(run, &opts, End::Failed(e)).await,
        };
        let cr = match self.call_credentials(c, run.id).await {
            Ok(cr) => cr,
            Err(e) => return self.end(run, &opts, End::Failed(e)).await,
        };
        if let Err(e) = self.audit_start(c, run.id).await {
            return self.end(run, &opts, End::Failed(e)).await;
        }
        let chunks = match discover(k.as_ref(), &cr).await {
            Ok(chunks) => chunks,
            Err(e) => return self.end(run, &opts, e).await,
        };
        let scan = Scan {
            fs: self,
            run_id: run.id,
            c,
            k: k.as_ref(),
            cr: &cr,
        };
        let ledger = self.uow.ledger();
        run_chunked(ledger, &self.redis, run.id, chunks, opts, |chunk, lease| {
            scan.chunk(chunk, lease.fence)
        })
        .await
    }

    /// The run's connection, in the organisation the run names.
    async fn connection(&self, run: &RunRow) -> Result<Connection> {
        let id = run.key.connection_id.ok_or(LedgerError::NotFound)?;
        let org = run.key.organisation_id.ok_or(LedgerError::NotFound)?;
        let c = self.uow.connections().get(org, id).await.map_err(lerr)?;
        c.ok_or(LedgerError::NotFound)
    }

    fn connector(&self, c: &Connection) -> Result<Arc<dyn Connector>> {
        if let Some(k) = &self.connector {
            return Ok(k.clone());
        }
        let k = self
            .registry
            .connector(&c.provider)
            .map_err(|e| job_err(&e))?;
        Ok(Arc::from(k))
    }

    /// `connection.scan_started`, once per run: a resumed or retried run does not repeat it.
    async fn audit_start(&self, c: &Connection, run_id: Uuid) -> Result<()> {
        const ACTION: &str = "connection.scan_started";
        let audit = self.uow.audit();
        let seen = audit.recorded_for_run(c.organisation_id, ACTION, run_id);
        if seen.await.map_err(lerr)? {
            return Ok(());
        }
        let target = ("connection", c.id.to_string());
        let entry = AuditEntry::system(c.organisation_id, ACTION, target, "success")
            .with_meta(json!({ "run_id": run_id }));
        audit.record(entry).await.map_err(lerr)
    }

    /// Decrypted call credentials; failures are not retryable.
    async fn call_credentials(&self, c: &Connection, run_id: Uuid) -> Result<Credentials> {
        let creds = creds::load(&*self.uow, self.kek.as_ref(), c.organisation_id, c.id)
            .await
            .map_err(|_| LedgerError::Job {
                code: "credentials_unavailable".into(),
                retry: false,
            })?;
        let context = CallContext {
            organisation_id: c.organisation_id,
            run_id,
            trigger: JOB.as_str().into(),
        };
        providers::credentials(&c.provider, &creds, context).map_err(|e| job_err(&e))
    }

    /// Sets the final status (or retries) under a lease of its own.
    async fn end(&self, run: &RunRow, opts: &RunChunkedOptions, how: End) -> Result<RunStatus> {
        let storage = self.uow.ledger();
        let l = lease::acquire(
            storage,
            &self.redis,
            run.id,
            &opts.worker_id,
            opts.lease_ttl,
        )
        .await?
        .ok_or(LedgerError::LeaseHeld)?;
        let res = match how {
            End::Set(status, reason) => storage
                .set_status(run.id, l.fence, status, Some(reason))
                .await
                .map(|()| status),
            End::Failed(e) => settle(storage, run.id, run.attempts, l.fence, &e).await,
        };
        let res = fail_on_storage_error(storage, run.id, l.fence, res).await;
        lease::release(&self.redis, &l).await;
        res
    }
}

/// The chunk list (`service@region`, then `simulate` and `finalize`) from an unscoped inventory call.
/// shortcut: re-run on every (re)start, which doubles the AWS calls; upgrade to a declared
/// connector scope when the AWS connector exposes one.
async fn discover(k: &dyn Connector, cr: &Credentials) -> std::result::Result<Vec<String>, End> {
    let inv = k.inventory(cr, &Scope::default()).await.map_err(|e| {
        if revoked(&e) {
            End::Set(RunStatus::Partial, "revoked".into())
        } else {
            End::Failed(job_err(&e))
        }
    })?;
    let mut chunks: Vec<String> = inv
        .resources
        .iter()
        .map(|r| (r.service(), r.region.as_str()))
        .chain(
            inv.partial_errors
                .iter()
                .map(|e| (e.service.as_str(), e.region.as_str())),
        )
        .map(|(s, r)| format!("{s}@{r}"))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    chunks.extend([SIMULATE.into(), FINALIZE.into()]);
    Ok(chunks)
}
