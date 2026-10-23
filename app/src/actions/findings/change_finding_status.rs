//! Customer actions on a finding (PRD 7.4): accept with a reason (default 90 days, at most 365),
//! snooze (at most 30 days), reopen. `decide` holds the rules; `run` persists one action.
use std::sync::Arc;

use axum::http::StatusCode;
use chrono::{DateTime, Duration, Utc};
use opsagent_core::{
    audit::AuditEntry,
    finding::{Finding, FindingEvent, StatusChange},
    repo::{Clock, RepoError},
};
use uuid::Uuid;

use crate::{
    actions::uow::UnitOfWork,
    error::{AppError, AppResult},
};

pub const ACCEPT_DEFAULT: Duration = Duration::days(90);
pub const ACCEPT_MAX: Duration = Duration::days(365);
pub const SNOOZE_MAX: Duration = Duration::days(30);
const REASON_MAX: usize = 1000;

#[derive(Debug, Clone)]
pub enum FindingAction {
    Accept {
        reason: Option<String>,
        until: Option<DateTime<Utc>>,
    },
    Snooze {
        until: DateTime<Utc>,
    },
    Reopen,
}

/// A finding's action fields after an action; the event type it records.
#[derive(Debug, PartialEq)]
struct Change {
    status: &'static str,
    event: &'static str,
    accepted_reason: Option<String>,
    accepted_until: Option<DateTime<Utc>>,
    snoozed_until: Option<DateTime<Utc>>,
}

fn until_within(until: DateTime<Utc>, now: DateTime<Utc>, max: Duration) -> AppResult<()> {
    if until <= now {
        return Err(AppError::Invalid("until must be in the future".into()));
    }
    if until > now + max {
        return Err(AppError::Invalid(format!(
            "until must be at most {} days ahead",
            max.num_days()
        )));
    }
    Ok(())
}

fn decide(status: &str, action: FindingAction, now: DateTime<Utc>) -> AppResult<Change> {
    if status == "resolved" {
        return Err(AppError::Invalid("the finding is resolved".into()));
    }
    let none = Change {
        status: "open",
        event: "reopened",
        accepted_reason: None,
        accepted_until: None,
        snoozed_until: None,
    };
    match action {
        FindingAction::Accept { reason, until } => {
            let reason = reason.as_deref().map(str::trim).unwrap_or_default();
            if reason.is_empty() || reason.chars().count() > REASON_MAX {
                return Err(AppError::Invalid(format!(
                    "reason is required (at most {REASON_MAX} characters)"
                )));
            }
            let until = until.unwrap_or(now + ACCEPT_DEFAULT);
            until_within(until, now, ACCEPT_MAX)?;
            Ok(Change {
                status: "accepted",
                event: "accepted",
                accepted_reason: Some(reason.to_owned()),
                accepted_until: Some(until),
                ..none
            })
        }
        FindingAction::Snooze { until } => {
            until_within(until, now, SNOOZE_MAX)?;
            Ok(Change {
                status: "snoozed",
                event: "snoozed",
                snoozed_until: Some(until),
                ..none
            })
        }
        FindingAction::Reopen if matches!(status, "accepted" | "snoozed") => Ok(none),
        FindingAction::Reopen => Err(AppError::Invalid(
            "only accepted or snoozed findings reopen".into(),
        )),
    }
}

/// A status change or a vanished row since the finding was read is the same 409.
fn cas_miss(e: RepoError) -> AppError {
    match e {
        RepoError::Conflict(_) | RepoError::NotFound => AppError::Refused {
            status: StatusCode::CONFLICT,
            code: "finding_state_changed",
            detail: "The finding changed while this request ran. Reload and try again.".into(),
        },
        e => e.into(),
    }
}

/// Applies one action for `actor`: status compare-and-set, event and audit row, one
/// transaction. Returns the updated finding.
pub struct ChangeFindingStatus {
    uow: Arc<dyn UnitOfWork>,
    clock: Arc<dyn Clock>,
}

impl ChangeFindingStatus {
    pub fn new(uow: Arc<dyn UnitOfWork>, clock: Arc<dyn Clock>) -> Self {
        Self { uow, clock }
    }

    pub async fn run(
        &self,
        organisation_id: Uuid,
        actor: Uuid,
        id: Uuid,
        action: FindingAction,
    ) -> AppResult<Finding> {
        let now = self.clock.now();
        let tx = self.uow.begin().await?;
        let f = tx
            .findings()
            .get(organisation_id, id)
            .await?
            .ok_or(AppError::NotFound)?;
        let c = decide(&f.status, action, now)?;
        let severity = Some(f.severity);
        let change = StatusChange {
            from_status: f.status,
            status: c.status.into(),
            accepted_reason: c.accepted_reason,
            accepted_until: c.accepted_until,
            snoozed_until: c.snoozed_until,
            event: FindingEvent {
                finding_id: id,
                kind: c.event.into(),
                run_id: None,
                from_severity: severity,
                to_severity: severity,
                at: now,
            },
        };
        let updated = tx
            .findings()
            .change_status(organisation_id, id, change)
            .await
            .map_err(cas_miss)?;
        tx.audit()
            .record(AuditEntry::member(
                Some(organisation_id),
                actor,
                format!("finding.{}", c.event),
                Some(("finding", id.to_string())),
            ))
            .await?;
        tx.commit().await?;
        Ok(updated)
    }
}

#[cfg(test)]
mod tests {
    use opsagent_core::repo::SystemClock;

    use super::*;
    use crate::{
        actions::{findings::test_support::seeded, uow::Repos},
        adapters::memory::MemStore,
        api_error::ApiError,
    };

    fn now() -> DateTime<Utc> {
        "2026-10-22T12:00:00Z".parse().unwrap()
    }

    fn accept(reason: Option<&str>, days: Option<i64>) -> FindingAction {
        FindingAction::Accept {
            reason: reason.map(Into::into),
            until: days.map(|d| now() + Duration::days(d)),
        }
    }

    fn snooze(days: i64) -> FindingAction {
        FindingAction::Snooze {
            until: now() + Duration::days(days),
        }
    }

    #[test]
    fn accept_needs_a_reason_and_defaults_to_90_days() {
        assert!(decide("open", accept(None, None), now()).is_err());
        assert!(decide("open", accept(Some("  "), None), now()).is_err());
        let c = decide("open", accept(Some(" lab "), None), now()).unwrap();
        assert_eq!((c.status, c.event), ("accepted", "accepted"));
        assert_eq!(c.accepted_reason.as_deref(), Some("lab"));
        assert_eq!(c.accepted_until, Some(now() + ACCEPT_DEFAULT));
        assert_eq!(c.snoozed_until, None);
    }

    #[test]
    fn accept_until_is_future_and_at_most_365_days() {
        assert!(decide("open", accept(Some("r"), Some(365)), now()).is_ok());
        assert!(decide("open", accept(Some("r"), Some(366)), now()).is_err());
        assert!(decide("open", accept(Some("r"), Some(0)), now()).is_err());
    }

    #[test]
    fn snooze_at_most_30_days_and_clears_acceptance() {
        let c = decide("accepted", snooze(30), now()).unwrap();
        assert_eq!((c.status, c.accepted_reason), ("snoozed", None));
        assert!(decide("open", snooze(31), now()).is_err());
        assert!(decide("open", snooze(-1), now()).is_err());
    }

    #[test]
    fn reopen_only_from_accepted_or_snoozed() {
        for s in ["accepted", "snoozed"] {
            let c = decide(s, FindingAction::Reopen, now()).unwrap();
            assert_eq!(
                (c.status, c.event, c.snoozed_until),
                ("open", "reopened", None)
            );
        }
        for s in ["open", "flapping"] {
            assert!(decide(s, FindingAction::Reopen, now()).is_err());
        }
    }

    #[test]
    fn cas_miss_is_409_for_changed_or_vanished_rows() {
        for e in [
            RepoError::Conflict("finding_state_changed"),
            RepoError::NotFound,
        ] {
            assert_eq!(ApiError::from(cas_miss(e)).code(), "finding_state_changed");
        }
        let other = ApiError::from(cas_miss(RepoError::Storage("x".into())));
        assert_ne!(other.code(), "finding_state_changed");
    }

    #[test]
    fn resolved_findings_take_no_action() {
        assert!(decide("resolved", accept(Some("r"), None), now()).is_err());
        assert!(decide("resolved", snooze(1), now()).is_err());
    }

    #[tokio::test]
    async fn snooze_of_resolved_finding_is_refused() {
        let store = MemStore::default();
        let (org, actor) = (Uuid::new_v4(), Uuid::new_v4());
        let (id, conn) = seeded(&store, org, "x").await;
        let later = Uuid::new_v4();
        let f = store.findings();
        f.resolve_unseen(org, conn, later, &[], Utc::now())
            .await
            .unwrap();
        let act = ChangeFindingStatus::new(Arc::new(store.clone()), Arc::new(SystemClock));
        let until = Utc::now() + Duration::days(1);
        let e = act
            .run(org, actor, id, FindingAction::Snooze { until })
            .await
            .unwrap_err();
        assert!(
            matches!(&e, AppError::Invalid(d) if d == "the finding is resolved"),
            "{e:?}"
        );
        assert_eq!(f.get(org, id).await.unwrap().unwrap().status, "resolved");
        assert!(store.audit_entries().is_empty());
    }

    #[tokio::test]
    async fn snooze_writes_status_event_and_audit_in_one_tx() {
        let store = MemStore::default();
        let (org, actor) = (Uuid::new_v4(), Uuid::new_v4());
        let (id, _) = seeded(&store, org, "x").await;
        let act = ChangeFindingStatus::new(Arc::new(store.clone()), Arc::new(SystemClock));
        let until = Utc::now() + Duration::days(1);
        let got = act
            .run(org, actor, id, FindingAction::Snooze { until })
            .await
            .unwrap();
        assert_eq!(
            (got.status.as_str(), got.snoozed_until),
            ("snoozed", Some(until))
        );
        let events = store.findings().events(org, id).await.unwrap();
        assert_eq!(events[0].kind, "snoozed");
        let audit = store.audit_entries();
        assert_eq!(audit.len(), 1);
        assert_eq!(
            (audit[0].action.as_str(), audit[0].actor),
            ("finding.snoozed", Some(actor))
        );
        let e = act
            .run(Uuid::new_v4(), actor, id, FindingAction::Reopen)
            .await
            .unwrap_err();
        assert!(matches!(e, AppError::NotFound), "{e:?}");
    }
}
