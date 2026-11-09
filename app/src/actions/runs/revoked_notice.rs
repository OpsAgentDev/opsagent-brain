//! The revoked-connection mail (PRD: "owners are emailed once"). An outbox run committed with
//! the status change, so a revocation that commits always mails and one that rolls back
//! never does; each owner's mail is one ledger effect, so a resumed run does not resend.
use std::sync::Arc;

use chrono::{DateTime, Utc};
use opsagent_core::{
    connection::{Connection, ConnectionStatus as S},
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

const SUBJECT: &str = "OpsAgent has lost access to a connected account";

/// Creates the notice run and job for `c`, on the transaction that revokes it. `at` is the
/// revocation instant, so each revocation has its own run.
pub async fn enqueue_revoked_notice(
    tx: &dyn Tx,
    c: &Connection,
    at: DateTime<Utc>,
) -> AppResult<()> {
    let kind = JobKind::DeliverRevokedNotice;
    let key = RunKey {
        organisation_id: Some(c.organisation_id),
        connection_id: Some(c.id),
        job_type: kind.as_str().into(),
        scheduled_at: at,
    };
    let out = tx.ledger().create_run(key).await?;
    if out.created {
        let job = NewJob {
            kind,
            run_id: out.run.id,
            run_at: at,
        };
        tx.queue().enqueue(job).await?;
    }
    Ok(())
}

/// `deliver_revoked_notice`: mails each owner once under the run's ledger lease.
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
        let org = run.key.organisation_id.ok_or(LedgerError::NotFound)?;
        let id = run.key.connection_id.ok_or(LedgerError::NotFound)?;
        let c = self.uow.connections().get(org, id).await.map_err(lerr)?;
        let Some(c) = c.filter(|c| c.status == S::Revoked) else {
            // The role came back, or the connection went, before the mail could go out.
            return Ok(stats(json!({ "skip_reason": "no_longer_revoked" })));
        };
        let text = self.body(&c);
        let link = self.link(&c);
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
            let key = format!("connection_revoked:{}", o.id);
            let mail = Mail {
                to: o.email,
                subject: SUBJECT.into(),
                html: Some(branded(SUBJECT, &text, Some(("Open connection", &link)))),
                text: text.clone(),
                idempotency_key: Some(format!("{}:{key}", run.id)),
                ..Default::default()
            };
            let sent = with_effect(self.uow.ledger(), run.id, &key, true, || async {
                self.mailer.send(mail).await.map_err(|_| {
                    tracing::warn!(error_code = "mail_failed", "revoked notice mail failed");
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

    fn link(&self, c: &Connection) -> String {
        let base = self.web_base_url.trim_end_matches('/');
        format!("{base}/connections/{}", c.id)
    }

    fn body(&self, c: &Connection) -> String {
        let name = c
            .display_name
            .as_deref()
            .map(mail_safe_name)
            .filter(|n| !n.is_empty())
            .or_else(|| c.external_account_id.clone())
            .unwrap_or_else(|| "your connected account".into());
        format!(
            "OpsAgent can no longer reach {name}: its role denied access on repeated checks, so \
             scans for it have stopped.\n\nRestore the role and OpsAgent will reconnect it \
             within a day. On a paid plan it stays billed for the current period, and is \
             disconnected at the period's end if access has not come back.\n\nOpen the \
             connection: {}",
            self.link(c)
        )
    }
}

fn stats(stats: serde_json::Value) -> ChunkOutcome {
    ChunkOutcome {
        stats,
        ..Default::default()
    }
}
