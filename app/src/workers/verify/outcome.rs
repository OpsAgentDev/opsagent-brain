//! Writing a verify outcome. Each outcome commits in one transaction that holds the run's
//! fence and sets the run's next status, so a killed worker leaves either nothing or the whole
//! outcome, and a superseded one cannot commit at all.
use chrono::Utc;
use opsagent_connectors::VerifyOutcome;
use opsagent_core::{
    connection::{transition, ConnectionEvent as E, ConnectionStatus as S},
    run::{RunKey, RunStatus},
};
use opsagent_ledger::{retry::retry_or_fail, Storage};
use sea_orm::{
    ActiveModelTrait, ConnectionTrait, DatabaseTransaction, Set, SqlErr, TransactionTrait,
};
use serde_json::json;
use uuid::Uuid;

use super::{
    verdict::{decide, Verdict},
    Step, VerifyWorker,
};
use crate::{
    models::{
        _entities::{connection_verifications, connections},
        audit,
        connections::{cas, status_str},
        ledger_storage::{hold_fence, PgStorage},
        now, schedules,
    },
    services::runs,
    workers::{
        common::{lerr, LResult},
        full_scan,
    },
};

/// Access denied must repeat this often, spanning at least `DENIED_SPAN`, before `revoked`.
const DENIED_TIMES: i32 = 3;
const DENIED_SPAN: chrono::TimeDelta = chrono::TimeDelta::hours(1);

fn is_unique_violation(e: &sea_orm::DbErr) -> bool {
    matches!(e.sql_err(), Some(SqlErr::UniqueConstraintViolation(_)))
}

impl VerifyWorker {
    /// A transaction holding the run's fence, with ledger writes on the same transaction.
    async fn fenced(&self, step: &Step<'_>) -> LResult<PgStorage<DatabaseTransaction>> {
        let tx = PgStorage::new(self.ctx.db.begin().await.map_err(lerr)?);
        hold_fence(tx.db(), step.run.id, step.fence).await?;
        Ok(tx)
    }

    /// Ends the run with `status` outside any outcome transaction (nothing else to write).
    async fn end(&self, step: &Step<'_>, status: RunStatus, reason: &str) -> LResult<()> {
        PgStorage::new(self.ctx.db.clone())
            .set_status(step.run.id, step.fence, status, Some(reason.into()))
            .await
    }

    /// Applies the verdict for a successful verify call.
    pub(super) async fn conclude(
        &self,
        step: &Step<'_>,
        status: S,
        account: Option<String>,
        o: &VerifyOutcome,
    ) -> LResult<()> {
        let (ev, reason) = match decide(o) {
            Verdict::Denied => return self.denied(step, status, o).await,
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
    async fn denied(&self, step: &Step<'_>, status: S, o: &VerifyOutcome) -> LResult<()> {
        let (run, c) = (step.run, step.c);
        let streak = c.verify_denied_streak + 1;
        let first = c.verify_denied_first_at.unwrap_or_else(now);
        let revoke = (streak >= DENIED_TIMES && now() - first >= DENIED_SPAN)
            .then(|| transition(status, E::AccessDeniedThrice).ok())
            .flatten();
        let mut a = <connections::ActiveModel as ActiveModelTrait>::default();
        a.verify_denied_streak = Set(streak);
        a.verify_denied_first_at = Set(Some(first));
        if let Some(to) = revoke {
            a.status = Set(status_str(to));
            a.status_reason = Set(Some("access_denied".into()));
            // TODO(notify): email owners once on revoked.
        }
        a.updated_at = Set(now());
        let tx = self.fenced(step).await?;
        if revoke.is_some() {
            // Daily re-checks while revoked, so a returned role recovers within a day.
            let now = Utc::now();
            let daily = schedules::VERIFY_REVOKED;
            schedules::set_cron(tx.db(), c.organisation_id, c.id, "verify", daily, |_| {
                Some(now)
            })
            .await
            .map_err(lerr)?;
        }
        if !cas(tx.db(), c, a).await.map_err(lerr)? {
            drop(tx);
            return self
                .end(step, RunStatus::Skipped, "connection_changed")
                .await;
        }
        let outcome = if revoke.is_some() {
            "revoked"
        } else {
            "access_denied"
        };
        self.record_in(tx.db(), c, run.id, Some(o), outcome, None)
            .await?;
        // Already revoked: the daily re-check found the role still gone; nothing to retry.
        if revoke.is_some() || status == S::Revoked {
            tx.set_status(run.id, step.fence, RunStatus::Done, None)
                .await?;
        } else {
            retry_or_fail(&tx, run.id, run.attempts, step.fence).await?;
        }
        tx.into_inner().commit().await.map_err(lerr)
    }

    /// Terminal error: status unchanged, `status_reason=verify_error:<code>`, error row, run failed.
    pub(super) async fn fail(&self, step: &Step<'_>, code: &str) -> LResult<()> {
        let (run, c) = (step.run, step.c);
        let tx = self.fenced(step).await?;
        let mut a = <connections::ActiveModel as ActiveModelTrait>::default();
        a.status_reason = Set(Some(format!("verify_error:{code}")));
        a.updated_at = Set(now());
        if cas(tx.db(), c, a).await.map_err(lerr)? {
            self.record_in(tx.db(), c, run.id, None, "error", Some(code))
                .await?;
        }
        let reason = Some(format!("verify_error:{code}"));
        tx.set_status(run.id, step.fence, RunStatus::Failed, reason)
            .await?;
        tx.into_inner().commit().await.map_err(lerr)
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
        let (run, c) = (step.run, step.c);
        let mut a = <connections::ActiveModel as ActiveModelTrait>::default();
        a.status = Set(status_str(to));
        a.status_reason = Set(reason);
        a.verify_denied_streak = Set(0);
        a.verify_denied_first_at = Set(None);
        a.updated_at = Set(now());
        if matches!(to, S::Connected | S::Degraded) {
            let account = account.ok_or_else(|| lerr("no account for role"))?;
            a.external_account_id = Set(Some(account));
        }
        let first_connect = to == S::Connected && c.first_connected_at.is_none();
        if first_connect {
            a.first_connected_at = Set(Some(now()));
            a.billable_from = Set(Some(now()));
        }
        let tx = self.fenced(step).await?;
        if to == S::Connected {
            self.connected_schedules(tx.db(), c).await?;
        }
        let Some(written) = self.write_status(tx.db(), c, a, to).await? else {
            return Ok(false);
        };
        self.record_in(tx.db(), c, run.id, Some(o), &status_str(written), None)
            .await?;
        let now = Utc::now();
        let first_scan = if first_connect && written == S::Connected {
            Some(
                runs::mark_new(&tx, first_scan_key(c, now), now)
                    .await
                    .map_err(lerr)?,
            )
        } else {
            None
        };
        tx.set_status(run.id, step.fence, RunStatus::Done, None)
            .await?;
        tx.into_inner().commit().await.map_err(lerr)?;
        // The first scan's run committed with its outbox marker; a lost hand-off is re-sent.
        if let Some(out) = first_scan.filter(|o| o.created) {
            runs::hand_off(&self.ctx, &out, full_scan::JOB, now).await;
        }
        Ok(true)
    }

    /// Default schedules, and the weekly verify back after a revoked spell.
    async fn connected_schedules(
        &self,
        db: &impl ConnectionTrait,
        c: &connections::Model,
    ) -> LResult<()> {
        let now = Utc::now();
        let (org, id) = (c.organisation_id, c.id);
        schedules::create_defaults(db, org, id, c.scan_time_local, now)
            .await
            .map_err(lerr)?;
        let weekly = schedules::VERIFY_WEEKLY;
        schedules::set_cron(db, org, id, "verify", weekly, |_| Some(now))
            .await
            .map_err(lerr)
    }

    /// The status CAS writing `a` (status `to`), or `blocked` when the account is already
    /// connected to another org. `None`: the connection changed since it was read.
    async fn write_status(
        &self,
        txn: &DatabaseTransaction,
        c: &connections::Model,
        a: connections::ActiveModel,
        to: S,
    ) -> LResult<Option<S>> {
        // Savepoint, so a unique violation does not abort the outer transaction.
        let sp = txn.begin().await.map_err(lerr)?;
        match cas(&sp, c, a).await {
            Ok(true) => {
                sp.commit().await.map_err(lerr)?;
                Ok(Some(to))
            }
            Ok(false) => Ok(None),
            Err(e) if is_unique_violation(&e) => {
                sp.rollback().await.map_err(lerr)?;
                // TODO(notify): email the owners of the organisation that holds the account.
                let blocked = connections::ActiveModel {
                    status: Set(status_str(S::Blocked)),
                    status_reason: Set(Some("account_already_connected".into())),
                    updated_at: Set(now()),
                    ..Default::default()
                };
                let ok = cas(txn, c, blocked).await.map_err(lerr)?;
                Ok(ok.then_some(S::Blocked))
            }
            Err(e) => Err(lerr(e)),
        }
    }

    /// One `connection_verifications` row plus the audit event, per verify outcome.
    async fn record_in(
        &self,
        db: &impl ConnectionTrait,
        c: &connections::Model,
        run_id: Uuid,
        o: Option<&VerifyOutcome>,
        outcome: &str,
        code: Option<&str>,
    ) -> LResult<()> {
        connection_verifications::ActiveModel {
            id: Set(Uuid::new_v4()),
            connection_id: Set(c.id),
            run_id: Set(Some(run_id)),
            assume_with_ok: Set(o.map(|o| o.assume_with_ok)),
            assume_without_denied: Set(o.map(|o| o.assume_without_denied)),
            policy_matches: Set(o.map(|o| o.extra_grants.is_empty() && o.missing_grants.is_empty())),
            extra_grants: Set(json!(o.map(|o| &o.extra_grants).cloned().unwrap_or_default())),
            missing_grants: Set(json!(o.map(|o| &o.missing_grants).cloned().unwrap_or_default())),
            outcome: Set(outcome.into()),
            created_at: Set(now()),
            updated_at: Set(now()),
        }
        .insert(db)
        .await
        .map_err(lerr)?;
        audit::record_system(
            db,
            c.organisation_id,
            "connection.verify_outcome",
            ("connection", c.id.to_string()),
            outcome,
            json!({ "run_id": run_id, "code": code }),
        )
        .await
        .map_err(lerr)
    }
}

/// The first scan right after the first connect.
fn first_scan_key(c: &connections::Model, now: chrono::DateTime<Utc>) -> RunKey {
    RunKey {
        organisation_id: Some(c.organisation_id),
        connection_id: Some(c.id),
        job_type: full_scan::JOB.into(),
        scheduled_at: now,
    }
}
