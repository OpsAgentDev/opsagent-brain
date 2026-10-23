//! On-demand `full_scan` for a connection, at most once per hour (any `full_scan` run counts).
use std::sync::Arc;

use axum::http::StatusCode;
use chrono::{DateTime, Duration, Utc};
use opsagent_core::{
    audit::AuditEntry, connection::ConnectionStatus as S, repo::Clock, run::RunKey,
};
use opsagent_ledger::{CreateRunOutcome, JobKind};
use uuid::Uuid;

use super::RunDispatcher;
use crate::{
    actions::uow::UnitOfWork,
    error::{AppError, AppResult},
    models::enum_str,
};

pub const WINDOW: Duration = Duration::hours(1);

/// Seconds until a scan is allowed again, if the last one was scheduled within the window.
fn retry_after(last: Option<DateTime<Utc>>, now: DateTime<Utc>) -> Option<u64> {
    let left = last? + WINDOW - now;
    (left > Duration::zero()).then(|| u64::try_from(left.num_seconds().max(1)).unwrap_or(1))
}

pub struct RequestManualScan {
    uow: Arc<dyn UnitOfWork>,
    dispatcher: Arc<RunDispatcher>,
    clock: Arc<dyn Clock>,
}

impl RequestManualScan {
    pub fn new(
        uow: Arc<dyn UnitOfWork>,
        dispatcher: Arc<RunDispatcher>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            uow,
            dispatcher,
            clock,
        }
    }

    /// For `actor`: creates the run (`scheduled_at = now`) and a `connection.scan_requested`
    /// audit row, or `rate_limited` within the window, or `connection_not_scannable` unless the
    /// connection is connected or degraded; the run's job commits with it. Runs under the
    /// connection row lock, so two concurrent requests create one run.
    pub async fn run(
        &self,
        organisation_id: Uuid,
        actor: Uuid,
        connection_id: Uuid,
    ) -> AppResult<CreateRunOutcome> {
        let now = self.clock.now();
        let tx = self.uow.begin().await?;
        let locked = tx
            .connections()
            .lock(organisation_id, connection_id)
            .await?;
        let c = locked.ok_or(AppError::NotFound)?;
        if !matches!(c.status, S::Connected | S::Degraded) {
            return Err(AppError::Refused {
                status: StatusCode::CONFLICT,
                code: "connection_not_scannable",
                detail: format!("A {} connection cannot be scanned.", enum_str(c.status)),
            });
        }
        let last = tx.runs().last_manual_scan(organisation_id, c.id).await?;
        if let Some(secs) = retry_after(last, now) {
            return Err(AppError::RateLimited {
                detail: "A scan ran for this connection within the last hour.".into(),
                retry_after_secs: secs,
            });
        }
        let key = RunKey {
            organisation_id: Some(organisation_id),
            connection_id: Some(c.id),
            job_type: JobKind::FullScan.as_str().into(),
            scheduled_at: now,
        };
        let out = self.dispatcher.create_and_enqueue(&*tx, key, now).await?;
        let target = Some(("connection", c.id.to_string()));
        let entry = AuditEntry::member(
            Some(organisation_id),
            actor,
            "connection.scan_requested",
            target,
        );
        tx.audit().record(entry).await?;
        tx.commit().await?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use opsagent_core::repo::FixedClock;

    use super::*;
    use crate::{actions::runs::test_support::connected, adapters::memory::MemStore};

    #[test]
    fn retry_after_counts_down_the_hour() {
        let now: DateTime<Utc> = "2026-10-22T12:00:00Z".parse().unwrap();
        assert_eq!(retry_after(None, now), None);
        assert_eq!(retry_after(Some(now), now), Some(3600));
        assert_eq!(
            retry_after(Some(now - Duration::minutes(59)), now),
            Some(60)
        );
        assert_eq!(retry_after(Some(now - Duration::minutes(60)), now), None);
        // A future scheduled run (clock skew) still blocks.
        assert!(retry_after(Some(now + Duration::minutes(5)), now).unwrap() > 3600);
    }

    #[tokio::test]
    async fn manual_scan_within_cooldown_is_rate_limited_with_retry_after() {
        let store = MemStore::default();
        let (org, actor) = (Uuid::new_v4(), Uuid::new_v4());
        let c = connected(&store, org).await;
        let d = Arc::new(RunDispatcher::new(Arc::new(store.clone())));
        let at = |t: DateTime<Utc>| {
            RequestManualScan::new(Arc::new(store.clone()), d.clone(), Arc::new(FixedClock(t)))
        };
        let first: DateTime<Utc> = "2026-10-22T12:00:00Z".parse().unwrap();
        let out = at(first).run(org, actor, c.id).await.unwrap();
        assert!(out.created);
        assert_eq!(store.jobs().len(), 1);
        let later = first + Duration::minutes(10);
        let err = at(later).run(org, actor, c.id).await.unwrap_err();
        assert!(
            matches!(
                err,
                AppError::RateLimited {
                    retry_after_secs: 3000,
                    ..
                }
            ),
            "{err:?}"
        );
        // Refused: no second run, no second audit row.
        assert_eq!(store.jobs().len(), 1);
        let audits = store.audit_entries();
        let scans = audits
            .iter()
            .filter(|e| e.action == "connection.scan_requested");
        assert_eq!(scans.count(), 1);
        let hour_on = first + WINDOW;
        assert!(at(hour_on).run(org, actor, c.id).await.unwrap().created);
    }
}
