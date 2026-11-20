//! The owners' connection notices: the revoked-connection mail (PRD: "owners are emailed
//! once"), the account-already-claimed mail (launch readiness H, 17b) and the scans-failing
//! mail (launch readiness K3). An outbox run
//! committed with the outcome, so an outcome that commits always mails and one that rolls back
//! never does; each owner's mail is one ledger effect, so a resumed run does not resend.
use std::sync::Arc;

use chrono::{DateTime, Utc};
use opsagent_core::{
    connection::{Connection, ConnectionStatus as S, SCANS_FAILING},
    org::org_web_base,
    run::{RunKey, RunStatus},
};
use opsagent_ledger::{
    effects::with_effect, redis, ChunkOutcome, JobKind, LedgerError, NewJob, RunChunkedOptions,
    RunRow,
};
use serde_json::json;
use uuid::Uuid;

use super::{
    classify::{lerr, LResult},
    one_chunk_run,
};
use crate::{
    actions::{
        recipients::MailGuard,
        uow::{Tx, UnitOfWork},
    },
    error::AppResult,
    mailers::{branded, magic_link::mail_safe_name, Mail, Mailer},
};

/// The notice a run sends, from its job type.
#[derive(Clone, Copy, PartialEq)]
enum Notice {
    Revoked,
    Claimed,
    ScansFailing,
}

impl Notice {
    fn of(run: &RunRow) -> LResult<Self> {
        match JobKind::parse(&run.key.job_type) {
            Some(JobKind::DeliverRevokedNotice) => Ok(Self::Revoked),
            Some(JobKind::DeliverClaimedNotice) => Ok(Self::Claimed),
            Some(JobKind::DeliverScansFailingNotice) => Ok(Self::ScansFailing),
            _ => Err(LedgerError::NotFound),
        }
    }

    fn subject(self) -> &'static str {
        match self {
            Self::Revoked => "OpsAgent has lost access to a connected account",
            Self::Claimed => "Another organisation tried to connect your cloud account",
            Self::ScansFailing => "OpsAgent could not finish its last three nightly scans",
        }
    }

    /// The owner's effect key prefix (unique per run, so per notice).
    fn effect(self) -> &'static str {
        match self {
            Self::Revoked => "connection_revoked",
            Self::Claimed => "account_claimed",
            Self::ScansFailing => SCANS_FAILING,
        }
    }

    /// `Err(skip_reason)` when the connection no longer is what the notice is about.
    fn applies(self, c: &Connection) -> Result<(), &'static str> {
        match self {
            Self::Revoked if c.status == S::Revoked => Ok(()),
            Self::Revoked => Err("no_longer_revoked"),
            Self::Claimed if matches!(c.status, S::Connected | S::Degraded | S::Revoked) => Ok(()),
            Self::Claimed => Err("no_longer_claimed"),
            Self::ScansFailing
                if c.status == S::Degraded && c.status_reason.as_deref() == Some(SCANS_FAILING) =>
            {
                Ok(())
            }
            Self::ScansFailing => Err("no_longer_failing"),
        }
    }
}

/// Creates the run of notice `kind` for `c` at `scheduled_at` and, when the run is new, its
/// job due at `run_at`: the run key is what makes a notice go out once.
async fn enqueue(
    tx: &dyn Tx,
    kind: JobKind,
    c: &Connection,
    scheduled_at: DateTime<Utc>,
    run_at: DateTime<Utc>,
) -> AppResult<()> {
    let key = RunKey {
        organisation_id: Some(c.organisation_id),
        connection_id: Some(c.id),
        job_type: kind.as_str().into(),
        scheduled_at,
    };
    let out = tx.ledger().create_run(key).await?;
    if out.created {
        let run_id = out.run.id;
        let job = NewJob {
            kind,
            run_id,
            run_at,
        };
        tx.queue().enqueue(job).await?;
    }
    Ok(())
}

/// Creates the notice run and job for `c`, on the transaction that revokes it. `at` is the
/// revocation instant, so each revocation has its own run.
pub async fn enqueue_revoked_notice(
    tx: &dyn Tx,
    c: &Connection,
    at: DateTime<Utc>,
) -> AppResult<()> {
    enqueue(tx, JobKind::DeliverRevokedNotice, c, at, at).await
}

/// Creates the notice run and job for `holder`, whose account `attempting` (another
/// organisation's connection) was just refused, on the transaction that blocks `attempting`.
/// Keyed to the holder and the attempting connection's creation instant, so repeated verifies
/// of `attempting` find the run and queue nothing. The run (and mail) never name `attempting`.
/// shortcut: two attempting connections created in the same microsecond share one notice;
/// key on the attempting id if `RunKey` ever gains a subject column.
pub async fn enqueue_claimed_notice(
    tx: &dyn Tx,
    holder: &Connection,
    attempting: &Connection,
    now: DateTime<Utc>,
) -> AppResult<()> {
    let kind = JobKind::DeliverClaimedNotice;
    enqueue(tx, kind, holder, attempting.created_at, now).await
}

/// Creates the notice run and job for `c`, on the transaction that degrades it for failing
/// scans. Keyed to `streak_from`, the first failed scan of the streak, so one streak has one
/// run however often it degrades the connection.
pub async fn enqueue_scans_failing_notice(
    tx: &dyn Tx,
    c: &Connection,
    streak_from: DateTime<Utc>,
    now: DateTime<Utc>,
) -> AppResult<()> {
    let kind = JobKind::DeliverScansFailingNotice;
    enqueue(tx, kind, c, streak_from, now).await
}

/// `deliver_revoked_notice`, `deliver_claimed_notice` and `deliver_scans_failing_notice`: mails
/// each owner once under the run's ledger lease.
#[derive(Clone)]
pub struct DeliverRevokedNotice {
    uow: Arc<dyn UnitOfWork>,
    redis: redis::Client,
    mailer: Arc<dyn Mailer>,
    guard: Arc<MailGuard>,
    web_base_url: String,
}

impl DeliverRevokedNotice {
    pub fn new(
        uow: Arc<dyn UnitOfWork>,
        redis: redis::Client,
        mailer: Arc<dyn Mailer>,
        guard: Arc<MailGuard>,
        web_base_url: String,
    ) -> Self {
        Self {
            uow,
            redis,
            mailer,
            guard,
            web_base_url,
        }
    }

    /// Runs (or resumes) notice run `run_id`. A failed mail ends the run `Queued` for a
    /// retry; owners already mailed are not mailed again.
    pub async fn run(&self, run_id: Uuid, opts: RunChunkedOptions) -> LResult<RunStatus> {
        let send = |run: RunRow| async move { self.send(&run).await };
        one_chunk_run(&*self.uow, &self.redis, run_id, opts, send).await
    }

    async fn send(&self, run: &RunRow) -> LResult<ChunkOutcome> {
        let notice = Notice::of(run)?;
        let org = run.key.organisation_id.ok_or(LedgerError::NotFound)?;
        let id = run.key.connection_id.ok_or(LedgerError::NotFound)?;
        let c = self.uow.connections().get(org, id).await.map_err(lerr)?;
        // The role came back, or the connection went, before the mail could go out.
        let Some(c) = c else {
            return Ok(stats(json!({ "skip_reason": "connection_gone" })));
        };
        if let Err(skip) = notice.applies(&c) {
            return Ok(stats(json!({ "skip_reason": skip })));
        }
        let slug = self.uow.orgs().get(org).await.map_err(lerr)?;
        let slug = slug.ok_or(LedgerError::NotFound)?.slug;
        let text = self.body(notice, &slug, &c);
        let subject = notice.subject();
        let link = self.link(&slug, &c);
        // Every owner is tried, so one bad address cannot hold back the rest.
        let mut failed = false;
        for o in self.uow.recipients().owners(org).await.map_err(lerr)? {
            if !self
                .guard
                .may_deliver(org, &o.email, o.member)
                .await
                .map_err(lerr)?
            {
                continue;
            }
            let key = format!("{}:{}", notice.effect(), o.id);
            let mail = Mail {
                to: o.email,
                subject: subject.into(),
                html: Some(branded(subject, &text, Some(("Open connection", &link)))),
                text: text.clone(),
                idempotency_key: Some(format!("{}:{key}", run.id)),
                ..Default::default()
            };
            let sent = with_effect(self.uow.ledger(), run.id, &key, true, || async {
                self.mailer.send(mail).await.map_err(|_| {
                    tracing::warn!(error_code = "mail_failed", "connection notice mail failed");
                    LedgerError::Job {
                        code: "mail_failed".into(),
                        retry: true,
                    }
                })?;
                Ok(None)
            })
            .await;
            match sent {
                Err(LedgerError::Job { .. }) => failed = true,
                other => drop(other?),
            }
        }
        if failed {
            return Err(LedgerError::Job {
                code: "mail_failed".into(),
                retry: true,
            });
        }
        Ok(stats(json!({ "mailed": true })))
    }

    fn link(&self, slug: &str, c: &Connection) -> String {
        format!(
            "{}/connections/{}",
            org_web_base(&self.web_base_url, slug),
            c.id
        )
    }

    fn body(&self, notice: Notice, slug: &str, c: &Connection) -> String {
        let name = c
            .display_name
            .as_deref()
            .map(mail_safe_name)
            .filter(|n| !n.is_empty());
        let account = c.external_account_id.as_deref().map(mail_safe_name);
        if notice == Notice::Claimed {
            return format!(
                "Another OpsAgent organisation tried to connect cloud account {} and was \
                 refused: it is already connected to your organisation as {}.\n\nNothing \
                 changed for your connection. If you did not expect this, check who can use \
                 the account's OpsAgent role.\n\nOpen the connection: {}",
                account.as_deref().unwrap_or("(unknown)"),
                name.as_deref().unwrap_or("your connection"),
                self.link(slug, c)
            );
        }
        let name = name
            .or(account)
            .unwrap_or_else(|| "your connected account".into());
        if notice == Notice::ScansFailing {
            return format!(
                "OpsAgent could not finish its last three nightly scans of {name}. Your findings \
                 may be out of date. We are looking into it; you do not need to do anything.\n\n\
                 Open the connection: {}",
                self.link(slug, c)
            );
        }
        format!(
            "OpsAgent can no longer reach {name}: its role denied access on repeated checks, so \
             scans for it have stopped.\n\nRestore the role and OpsAgent will reconnect it \
             within a day. On a paid plan it stays billed for the current period, and is \
             disconnected at the period's end if access has not come back.\n\nOpen the \
             connection: {}",
            self.link(slug, c)
        )
    }
}

fn stats(stats: serde_json::Value) -> ChunkOutcome {
    ChunkOutcome {
        stats,
        ..Default::default()
    }
}
