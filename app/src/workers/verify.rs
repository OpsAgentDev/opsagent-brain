//! `verify` job: assume the customer role, diff the policy, set the connection status (PRD 7.2).
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use loco_rs::{app::AppContext, bgworker::BackgroundWorker, Result};
use opsagent_connectors::{registry as providers, CallContext, Connector, VerifyOutcome};
use opsagent_core::{
    connection::{transition, ConnectionEvent as E, ConnectionStatus as S},
    run::RunStatus,
};
use opsagent_ledger::{lease, LedgerError, RunRow, Storage};
use sea_orm::{ActiveModelTrait, ConnectionTrait, EntityTrait, Set, SqlErr, TransactionTrait};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use super::common::{classify, connector_for, err, lerr, redis_client, retry, LResult};
use crate::{
    app::kek,
    models::{
        _entities::{connection_verifications, connections},
        audit,
        connections::{cas, load_creds, status_of, status_str},
        ledger_storage::PgStorage,
        now, schedules,
    },
};

const LEASE_TTL: Duration = Duration::from_secs(120);
/// Access denied must repeat this often, spanning at least `DENIED_SPAN`, before `revoked`.
const DENIED_TIMES: i32 = 3;
const DENIED_SPAN: chrono::TimeDelta = chrono::TimeDelta::hours(1);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyArgs {
    pub run_id: Uuid,
}

pub struct VerifyWorker {
    ctx: AppContext,
}

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// Role assume with the ExternalId was denied.
    Denied,
    Event(E, Option<String>),
}

fn names(grants: &[String]) -> String {
    grants
        .iter()
        .map(|g| g.split(" on ").next().unwrap_or(g))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Order matters: the confused-deputy guard wins over everything else.
fn decide(o: &VerifyOutcome) -> Verdict {
    if !o.assume_without_denied {
        Verdict::Event(
            E::ExternalIdNotEnforced,
            Some("external_id_not_enforced".into()),
        )
    } else if !o.assume_with_ok {
        Verdict::Denied
    } else if !o.account_matches {
        // No dedicated event: an account mismatch is blocked exactly like a superset.
        Verdict::Event(E::VerifySuperset, Some("account_mismatch".into()))
    } else if !o.extra_grants.is_empty() {
        let reason = format!("extra_grants: {}", names(&o.extra_grants));
        Verdict::Event(E::VerifySuperset, Some(reason))
    } else if !o.missing_grants.is_empty() {
        let reason = format!("missing_grants: {}", names(&o.missing_grants));
        Verdict::Event(E::VerifySubset, Some(reason))
    } else {
        Verdict::Event(E::VerifyOk, None)
    }
}

fn is_unique_violation(e: &sea_orm::DbErr) -> bool {
    matches!(e.sql_err(), Some(SqlErr::UniqueConstraintViolation(_)))
}

#[async_trait]
impl BackgroundWorker<VerifyArgs> for VerifyWorker {
    fn build(ctx: &AppContext) -> Self {
        Self { ctx: ctx.clone() }
    }

    async fn perform(&self, args: VerifyArgs) -> Result<()> {
        let k = connector_for(&self.ctx, args.run_id).await?;
        verify(&self.ctx, args.run_id, k.as_ref()).await
    }
}

/// Runs (or re-runs) verify run `run_id` with connector `k` under a fenced lease.
pub async fn verify(ctx: &AppContext, run_id: Uuid, k: &dyn Connector) -> Result<()> {
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
    let res = w.run(&storage, &run, lease.fence, k).await;
    lease::release(&redis, &lease).await;
    match res {
        Ok(()) | Err(LedgerError::StaleFence) => Ok(()),
        Err(e) => Err(err(e)),
    }
}

impl VerifyWorker {
    async fn run(
        &self,
        storage: &PgStorage,
        run: &RunRow,
        fence: u64,
        k: &dyn Connector,
    ) -> LResult<()> {
        storage
            .set_status(run.id, fence, RunStatus::Running, None)
            .await?;
        let db = &self.ctx.db;
        let conn_id = run.key.connection_id.ok_or(LedgerError::NotFound)?;
        let c = connections::Entity::find_by_id(conn_id)
            .one(db)
            .await
            .map_err(lerr)?
            .ok_or(LedgerError::NotFound)?;
        let status = status_of(&c).map_err(lerr)?;
        if matches!(status, S::Pending | S::Disconnected) {
            let reason = Some(format!("connection_{}", c.status));
            return storage
                .set_status(run.id, fence, RunStatus::Skipped, reason)
                .await;
        }
        let kek = kek(&self.ctx).map_err(lerr)?;
        let creds = load_creds(db, kek.as_ref(), &c).await.map_err(lerr)?;
        let context = CallContext {
            organisation_id: c.organisation_id,
            run_id: run.id,
            trigger: "verify".into(),
        };
        let outcome = match providers::credentials(&c.provider, &creds, context) {
            Ok(cr) => k.verify(&cr).await.map(|o| (o, cr)),
            Err(e) => Err(e),
        };
        let (o, cr) = match outcome {
            Ok(v) => v,
            // Throttling and 5xx: retry, never change state.
            Err(e) => {
                let (code, transient) = classify(&e);
                tracing::warn!(error = %e, run = %run.id, code, transient, "verify: connector error");
                // Throttling, 5xx and network: retry without changing state, until exhausted.
                if transient && retry(storage, run, fence).await? {
                    return Ok(());
                }
                return self.fail(storage, run, fence, &c, &code).await;
            }
        };
        match decide(&o) {
            Verdict::Denied => self.denied(storage, run, fence, &c, status, &o).await,
            Verdict::Event(ev, reason) => {
                let to = match transition(status, ev) {
                    Ok(to) => to,
                    Err(e) => {
                        return storage
                            .set_status(run.id, fence, RunStatus::Skipped, Some(e.to_string()))
                            .await
                    }
                };
                let (st, why) = if self.apply(&c, cr.account(), run.id, to, reason, &o).await? {
                    (RunStatus::Done, None)
                } else {
                    (RunStatus::Skipped, Some("connection_changed".into()))
                };
                storage.set_status(run.id, fence, st, why).await
            }
        }
    }

    /// Consecutive denials; `revoked` only once they repeat 3 times over at least an hour.
    async fn denied(
        &self,
        storage: &PgStorage,
        run: &RunRow,
        fence: u64,
        c: &connections::Model,
        status: S,
        o: &VerifyOutcome,
    ) -> LResult<()> {
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
        let txn = self.ctx.db.begin().await.map_err(lerr)?;
        if !cas(&txn, c, a).await.map_err(lerr)? {
            return storage
                .set_status(
                    run.id,
                    fence,
                    RunStatus::Skipped,
                    Some("connection_changed".into()),
                )
                .await;
        }
        let outcome = if revoke.is_some() {
            "revoked"
        } else {
            "access_denied"
        };
        self.record_in(&txn, c, run.id, Some(o), outcome, None)
            .await?;
        txn.commit().await.map_err(lerr)?;
        if revoke.is_some() {
            storage
                .set_status(run.id, fence, RunStatus::Done, None)
                .await
        } else {
            retry(storage, run, fence).await.map(|_| ())
        }
    }

    /// Terminal error: status unchanged, `status_reason=verify_error:<code>`, error row, run failed.
    async fn fail(
        &self,
        storage: &PgStorage,
        run: &RunRow,
        fence: u64,
        c: &connections::Model,
        code: &str,
    ) -> LResult<()> {
        let txn = self.ctx.db.begin().await.map_err(lerr)?;
        let mut a = <connections::ActiveModel as ActiveModelTrait>::default();
        a.status_reason = Set(Some(format!("verify_error:{code}")));
        a.updated_at = Set(now());
        if cas(&txn, c, a).await.map_err(lerr)? {
            self.record_in(&txn, c, run.id, None, "error", Some(code))
                .await?;
        }
        txn.commit().await.map_err(lerr)?;
        let reason = Some(format!("verify_error:{code}"));
        storage
            .set_status(run.id, fence, RunStatus::Failed, reason)
            .await
    }

    async fn apply(
        &self,
        c: &connections::Model,
        account: Option<String>,
        run_id: Uuid,
        to: S,
        reason: Option<String>,
        o: &VerifyOutcome,
    ) -> LResult<bool> {
        let txn = self.ctx.db.begin().await.map_err(lerr)?;
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
        if to == S::Connected && c.first_connected_at.is_none() {
            a.first_connected_at = Set(Some(now()));
            a.billable_from = Set(Some(now()));
            // TODO(full_scan): enqueue the first scan on first connect (Task 10).
        }
        if to == S::Connected {
            schedules::create_defaults(&txn, c.organisation_id, c.id, Utc::now())
                .await
                .map_err(lerr)?;
        }
        // Savepoint, so a unique violation does not abort the outer transaction.
        let sp = txn.begin().await.map_err(lerr)?;
        let outcome = match cas(&sp, c, a).await {
            Ok(true) => {
                sp.commit().await.map_err(lerr)?;
                status_str(to)
            }
            Ok(false) => return Ok(false),
            Err(e) if is_unique_violation(&e) => {
                sp.rollback().await.map_err(lerr)?;
                // TODO(notify): email the owners of the organisation that holds the account.
                let blocked = connections::ActiveModel {
                    status: Set(status_str(S::Blocked)),
                    status_reason: Set(Some("account_already_connected".into())),
                    updated_at: Set(now()),
                    ..Default::default()
                };
                if !cas(&txn, c, blocked).await.map_err(lerr)? {
                    return Ok(false);
                }
                status_str(S::Blocked)
            }
            Err(e) => return Err(lerr(e)),
        };
        self.record_in(&txn, c, run_id, Some(o), &outcome, None)
            .await?;
        txn.commit().await.map_err(lerr)?;
        Ok(true)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn ok() -> VerifyOutcome {
        VerifyOutcome {
            assume_with_ok: true,
            assume_without_denied: true,
            account_matches: true,
            extra_grants: vec![],
            missing_grants: vec![],
        }
    }

    #[test]
    fn decide_maps_outcomes_in_priority_order() {
        assert_eq!(decide(&ok()), Verdict::Event(E::VerifyOk, None));
        let open = VerifyOutcome {
            assume_without_denied: false,
            assume_with_ok: false,
            ..ok()
        };
        assert_eq!(
            decide(&open),
            Verdict::Event(
                E::ExternalIdNotEnforced,
                Some("external_id_not_enforced".into())
            )
        );
        let denied = VerifyOutcome {
            assume_with_ok: false,
            ..ok()
        };
        assert_eq!(decide(&denied), Verdict::Denied);
        let other = VerifyOutcome {
            account_matches: false,
            extra_grants: vec!["ec2:RunInstances on *".into()],
            ..ok()
        };
        assert_eq!(
            decide(&other),
            Verdict::Event(E::VerifySuperset, Some("account_mismatch".into()))
        );
        let both = VerifyOutcome {
            extra_grants: vec!["ec2:RunInstances on *".into()],
            missing_grants: vec!["ec2:Describe* on *".into()],
            ..ok()
        };
        assert_eq!(
            decide(&both),
            Verdict::Event(
                E::VerifySuperset,
                Some("extra_grants: ec2:RunInstances".into())
            )
        );
        let subset = VerifyOutcome {
            missing_grants: vec!["ec2:Describe* on *".into()],
            ..ok()
        };
        assert_eq!(
            decide(&subset),
            Verdict::Event(
                E::VerifySubset,
                Some("missing_grants: ec2:Describe*".into())
            )
        );
    }
}
