//! Writing a verify outcome. Each outcome commits in one transaction that holds the run's
//! fence and sets the run's next status, so a killed worker leaves either nothing or the whole
//! outcome, and a superseded one cannot commit at all.
use chrono::{DateTime, Utc};
use opsagent_connectors::VerifyOutcome;
use opsagent_core::{
    audit::AuditEntry,
    connection::{
        transition, Connection, ConnectionEvent as E, ConnectionStatus as S, Verification, Verified,
    },
    repo::RepoError,
    run::{RunKey, RunStatus},
};
use opsagent_deliver::schedule;
use opsagent_ledger::{retry::retry_or_fail, JobKind};
use serde_json::json;
use uuid::Uuid;

use super::{
    classify::{lerr, LResult},
    verify_connection::{Step, VerifyConnection},
    verify_verdict::{decide, Verdict},
};
use crate::{actions::uow::Tx, models::enum_str};

/// Access denied must repeat this often, spanning at least `DENIED_SPAN`, before `revoked`.
const DENIED_TIMES: i32 = 3;
const DENIED_SPAN: chrono::TimeDelta = chrono::TimeDelta::hours(1);

impl VerifyConnection {
    /// A transaction holding the run's fence, with ledger writes on the same transaction.
    async fn fenced(&self, step: &Step<'_>) -> LResult<Box<dyn Tx>> {
        let tx = self.uow.begin().await.map_err(lerr)?;
        tx.hold_fence(step.run.id, step.fence).await?;
        Ok(tx)
    }

    /// Ends the run with `status` outside any outcome transaction (nothing else to write).
    async fn end(&self, step: &Step<'_>, status: RunStatus, reason: &str) -> LResult<()> {
        let ledger = self.uow.ledger();
        ledger
            .set_status(step.run.id, step.fence, status, Some(reason.into()))
            .await
    }

    /// Applies the verdict for a successful verify call.
    pub(super) async fn conclude(
        &self,
        step: &Step<'_>,
        account: Option<String>,
        o: &VerifyOutcome,
    ) -> LResult<()> {
        let status = step.c.status;
        let (ev, reason) = match decide(o) {
            Verdict::Denied => return self.denied(step, o).await,
            Verdict::Event(ev, reason) => (ev, reason),
        };
        // A revoked connection whose role works again is re-verified in full (RoleReturned).
        let from = match status {
            S::Revoked => transition(status, E::RoleReturned).map_err(lerr)?,
            s => s,
        };
        let to = match transition(from, ev) {
            Ok(to) => to,
            Err(e) => return self.end(step, RunStatus::Skipped, &e.to_string()).await,
        };
        if !self.apply(step, (to, reason), account, o).await? {
            return self
                .end(step, RunStatus::Skipped, "connection_changed")
                .await;
        }
        Ok(())
    }

    /// Consecutive denials; `revoked` only once they repeat 3 times over at least an hour.
    async fn denied(&self, step: &Step<'_>, o: &VerifyOutcome) -> LResult<()> {
        let (run, c, now) = (step.run, step.c, self.clock.now());
        let streak = c.verify_denied_streak + 1;
        let first = c.verify_denied_first_at.unwrap_or(now);
        let revoke = (streak >= DENIED_TIMES && now - first >= DENIED_SPAN)
            .then(|| transition(c.status, E::AccessDeniedThrice).ok())
            .flatten();
        let tx = self.fenced(step).await?;
        if revoke.is_some() {
            // Daily re-checks while revoked, so a returned role recovers within a day.
            let daily = schedule::VERIFY_REVOKED;
            tx.schedules()
                .set_cron(c.organisation_id, c.id, "verify", daily, &|_| Some(now))
                .await
                .map_err(lerr)?;
        }
        // TODO(notify): email owners once on revoked.
        let (to, reason) = revoke.map_or((c.status, None), |to| (to, Some("access_denied")));
        let repo = tx.connections();
        let cas = repo.cas_status(c.organisation_id, c.id, c.status, to, reason);
        if !cas.await.map_err(lerr)? {
            drop(tx);
            return self
                .end(step, RunStatus::Skipped, "connection_changed")
                .await;
        }
        repo.record_denial(c.organisation_id, c.id, streak, first)
            .await
            .map_err(lerr)?;
        let outcome = if revoke.is_some() {
            "revoked"
        } else {
            "access_denied"
        };
        self.record(&*tx, c, run.id, Some(o), outcome, None).await?;
        // Already revoked: the daily re-check found the role still gone; nothing to retry.
        if revoke.is_some() || c.status == S::Revoked {
            tx.ledger()
                .set_status(run.id, step.fence, RunStatus::Done, None)
                .await?;
        } else {
            retry_or_fail(tx.ledger(), run.id, run.attempts, step.fence).await?;
        }
        tx.commit().await.map_err(lerr)
    }

    /// Terminal error: status unchanged, `status_reason=verify_error:<code>`, error row, run failed.
    pub(super) async fn fail(&self, step: &Step<'_>, code: &str) -> LResult<()> {
        let (run, c) = (step.run, step.c);
        let tx = self.fenced(step).await?;
        let reason = format!("verify_error:{code}");
        let cas =
            tx.connections()
                .cas_status(c.organisation_id, c.id, c.status, c.status, Some(&reason));
        if cas.await.map_err(lerr)? {
            self.record(&*tx, c, run.id, None, "error", Some(code))
                .await?;
        }
        tx.ledger()
            .set_status(run.id, step.fence, RunStatus::Failed, Some(reason))
            .await?;
        tx.commit().await.map_err(lerr)
    }

    /// Writes status `to` (or `blocked` when another org holds the account), the record and
    /// the run's `done`, and on a first connect the first scan's run. `false`: the connection
    /// changed since it was read, nothing written.
    async fn apply(
        &self,
        step: &Step<'_>,
        (to, reason): (S, Option<String>),
        account: Option<String>,
        o: &VerifyOutcome,
    ) -> LResult<bool> {
        let (run, c, now) = (step.run, step.c, self.clock.now());
        let account = match to {
            S::Connected | S::Degraded => Some(account.ok_or_else(|| lerr("no account for role"))?),
            _ => None,
        };
        let first_connect = to == S::Connected && c.first_connected_at.is_none();
        let v = Verified {
            account,
            reason,
            first_connected_at: first_connect.then_some(now),
        };
        let tx = self.fenced(step).await?;
        let Some(written) = self.claim(&*tx, c, to, v).await? else {
            return Ok(false);
        };
        self.outcome_schedules(&*tx, c, written, now).await?;
        self.record(&*tx, c, run.id, Some(o), &enum_str(written), None)
            .await?;
        let first_scan = if first_connect && written == S::Connected {
            let key = first_scan_key(c, now);
            let out = self.dispatcher.create_marked(&*tx, key, now).await;
            Some(out.map_err(lerr)?)
        } else {
            None
        };
        tx.ledger()
            .set_status(run.id, step.fence, RunStatus::Done, None)
            .await?;
        tx.commit().await.map_err(lerr)?;
        // The first scan's run committed with its outbox marker; a lost hand-off is re-sent.
        if let Some(out) = first_scan.filter(|o| o.created) {
            self.dispatcher.hand_off(&out, now).await;
        }
        Ok(true)
    }

    /// The status CAS to `to` with what the call established, or `blocked` when the account
    /// is already claimed by another connection. `None`: the connection changed since it was read.
    async fn claim(&self, tx: &dyn Tx, c: &Connection, to: S, v: Verified) -> LResult<Option<S>> {
        let (org, id) = (c.organisation_id, c.id);
        // Savepoint, so a refused account does not abort the outcome transaction.
        let sp = tx.savepoint().await.map_err(lerr)?;
        let claimed = match sp.connections().record_verified(org, id, v).await {
            Ok(()) => {
                sp.connections()
                    .cas_status(org, id, c.status, to, None)
                    .await
            }
            Err(e) => Err(e),
        };
        match claimed {
            Ok(true) => {
                sp.commit().await.map_err(lerr)?;
                Ok(Some(to))
            }
            Ok(false) => Ok(None),
            Err(RepoError::Conflict("account")) => {
                drop(sp); // back to the savepoint
                          // TODO(notify): email the owners of the organisation that holds the account.
                let reason = Some("account_already_connected");
                let cas = tx
                    .connections()
                    .cas_status(org, id, c.status, S::Blocked, reason);
                Ok(cas.await.map_err(lerr)?.then_some(S::Blocked))
            }
            Err(e) => Err(lerr(e)),
        }
    }

    /// Default schedules once the connection is connected (never for `blocked`); and
    /// on any outcome here (none is `revoked`) the weekly verify back after a revoked spell.
    async fn outcome_schedules(
        &self,
        tx: &dyn Tx,
        c: &Connection,
        written: S,
        now: DateTime<Utc>,
    ) -> LResult<()> {
        let (org, id, schedules) = (c.organisation_id, c.id, tx.schedules());
        if written == S::Connected {
            let times = (c.scan_time_local, c.briefing_time_local);
            schedules
                .create_defaults(org, id, times, now)
                .await
                .map_err(lerr)?;
        }
        let weekly = schedule::VERIFY_WEEKLY;
        schedules
            .set_cron(org, id, "verify", weekly, &|_| Some(now))
            .await
            .map_err(lerr)
    }

    /// One verification record plus the audit event, per verify outcome.
    async fn record(
        &self,
        tx: &dyn Tx,
        c: &Connection,
        run_id: Uuid,
        o: Option<&VerifyOutcome>,
        outcome: &str,
        code: Option<&str>,
    ) -> LResult<()> {
        let grants = |g: Option<&Vec<String>>| json!(g.cloned().unwrap_or_default());
        let v = Verification {
            outcome: outcome.into(),
            at: self.clock.now(),
            assume_with_ok: o.map(|o| o.assume_with_ok),
            assume_without_denied: o.map(|o| o.assume_without_denied),
            policy_matches: o.map(|o| o.extra_grants.is_empty() && o.missing_grants.is_empty()),
            extra_grants: grants(o.map(|o| &o.extra_grants)),
            missing_grants: grants(o.map(|o| &o.missing_grants)),
        };
        let org = c.organisation_id;
        tx.connections()
            .record_verification(org, c.id, run_id, &v)
            .await
            .map_err(lerr)?;
        let entry = AuditEntry::system(
            org,
            "connection.verify_outcome",
            ("connection", c.id.to_string()),
            outcome,
        );
        let entry = entry.with_meta(json!({ "run_id": run_id, "code": code }));
        tx.audit().record(entry).await.map_err(lerr)
    }
}

/// The first scan right after the first connect.
fn first_scan_key(c: &Connection, now: DateTime<Utc>) -> RunKey {
    RunKey {
        organisation_id: Some(c.organisation_id),
        connection_id: Some(c.id),
        job_type: JobKind::FullScan.as_str().into(),
        scheduled_at: now,
    }
}
