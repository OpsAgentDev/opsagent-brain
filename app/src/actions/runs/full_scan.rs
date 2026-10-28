//! `full_scan` (PRD 7.3, jobs.md): one chunk per service × region, then a `finalize` chunk
//! that marks unseen resources gone, runs the checks and applies the finding lifecycle.
//! The same action runs `watch_scan` under `ScanProfile::Watch` (see `watch_scan`).
use std::{collections::BTreeSet, sync::Arc};

use opsagent_checks::Check;
use opsagent_connectors::{registry as providers, CallContext, Connector, Credentials, Scope};
use opsagent_core::{
    audit::AuditEntry,
    connection::{Connection, ConnectionStatus as S},
    repo::Clock,
    run::RunStatus,
};
use opsagent_ledger::{
    lease::{self, claim, is_claimed, unclaim},
    redis,
    retry::{fail_on_storage_error, settle},
    run_chunked, JobKind, LedgerError, Result, RunChunkedOptions, RunRow,
};
use opsagent_secrets::Kek;
use serde_json::json;
use uuid::Uuid;

use super::{
    full_scan_chunks::{Scan, FINALIZE, SIMULATE},
    watch_scan::WATCH_SERVICES,
};
use crate::{
    actions::runs::classify::{job_err, lerr, revoked},
    actions::{uow::UnitOfWork, ConnectorSource},
    creds,
    models::enum_str,
};

pub(super) const JOB: JobKind = JobKind::FullScan;

/// Which scan a `FullScan` runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ScanProfile {
    /// Every service and check; resolves, marks gone and scores.
    Full,
    /// `watch_scan`: the watch services and variants only; never resolves, marks gone or scores.
    Watch,
}

/// Runs (or resumes) the scan of one run. Clone it to override the connector or the checks.
#[derive(Clone)]
pub struct FullScan {
    pub(super) uow: Arc<dyn UnitOfWork>,
    redis: redis::Client,
    kek: Arc<dyn Kek>,
    connectors: Arc<dyn ConnectorSource>,
    pub(super) clock: Arc<dyn Clock>,
    connector: Option<Arc<dyn Connector>>,
    pub(super) checks: fn() -> Vec<Box<dyn Check>>,
    pub(super) profile: ScanProfile,
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
        connectors: Arc<dyn ConnectorSource>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            uow,
            redis,
            kek,
            connectors,
            clock,
            connector: None,
            checks: opsagent_checks::all,
            profile: ScanProfile::Full,
        }
    }

    /// The same scan as a `watch_scan`.
    pub fn watch(self) -> Self {
        Self {
            profile: ScanProfile::Watch,
            ..self
        }
    }

    fn job(&self) -> JobKind {
        match self.profile {
            ScanProfile::Full => JobKind::FullScan,
            ScanProfile::Watch => JobKind::WatchScan,
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
        if self.profile == ScanProfile::Watch {
            if let Some(skip) = self.watch_gate(&c).await? {
                return self.end(&run, &opts, skip).await;
            }
        }
        // At most one scan of each kind per connection (PRD 7.3); the run id owns the claim,
        // so a resumed run passes and any other run is skipped.
        let (key, owner) = (lease_key(c.id, self.job()), run_id.to_string());
        if !claim(&self.redis, &key, &owner, opts.time_cap + opts.lease_ttl).await? {
            let skip = End::Set(RunStatus::Skipped, "overlap".into());
            return self.end(&run, &opts, skip).await;
        }
        let res = self.claimed(&run, &c, opts).await;
        let after = self.uow.ledger().load_run(run_id).await;
        if self.profile == ScanProfile::Watch
            && after
                .as_ref()
                .is_ok_and(|r| r.partial_reason.as_deref() == Some("time_cap"))
        {
            tracing::warn!(connection = %c.id, run = %run_id, "watch_scan: time cap hit before finalize");
        }
        // A worker that took over this run's lease is still scanning: leave the claim to it.
        if !matches!(after.map(|r| r.status), Ok(RunStatus::Running)) {
            unclaim(&self.redis, &key, &owner).await;
        }
        res
    }

    /// Why a watch scan must not run now: before the connection's first completed full scan
    /// (its criticals are the baseline), or while a full scan holds the connection. A full
    /// scan never waits for a watch scan.
    async fn watch_gate(&self, c: &Connection) -> Result<Option<End>> {
        let done = self.uow.runs().completed_full_scan(c.organisation_id, c.id);
        let skip = |why: &str| Some(End::Set(RunStatus::Skipped, why.into()));
        if !done.await.map_err(lerr)? {
            return Ok(skip("no_baseline"));
        }
        if is_claimed(&self.redis, &lease_key(c.id, JobKind::FullScan)).await? {
            return Ok(skip("overlap"));
        }
        Ok(None)
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
        // shortcut: watch scans (every 15 min) skip `connection.scan_started`, or they would
        // flood the audit log; audit them when the audit view can filter by run kind.
        if self.profile == ScanProfile::Full {
            if let Err(e) = self.audit_start(c, run.id).await {
                return self.end(run, &opts, End::Failed(e)).await;
            }
        }
        let chunks = match discover(k.as_ref(), &cr, self.profile).await {
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
        self.connectors
            .connector(&c.provider)
            .map_err(|e| job_err(&e))
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
            trigger: self.job().as_str().into(),
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

fn lease_key(connection_id: Uuid, job: JobKind) -> String {
    format!("lease:conn:{connection_id}:{}", job.as_str())
}

/// The chunk list (`service@region`, then `simulate` and `finalize`; a watch scan has no
/// `simulate`) from one inventory call over the profile's services.
/// shortcut: re-run on every (re)start, which doubles the AWS calls; upgrade to a declared
/// connector scope when the AWS connector exposes one.
async fn discover(
    k: &dyn Connector,
    cr: &Credentials,
    profile: ScanProfile,
) -> std::result::Result<Vec<String>, End> {
    let scope = match profile {
        ScanProfile::Full => Scope::default(),
        ScanProfile::Watch => Scope {
            regions: vec![],
            services: WATCH_SERVICES.map(String::from).to_vec(),
        },
    };
    let inv = k.inventory(cr, &scope).await.map_err(|e| {
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
    if profile == ScanProfile::Full {
        chunks.push(SIMULATE.into());
    }
    chunks.push(FINALIZE.into());
    Ok(chunks)
}
