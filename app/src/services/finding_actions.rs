//! Customer actions on a finding (PRD 7.4): accept with a reason (default 90 days, at most 365),
//! snooze (at most 30 days), reopen. `decide` holds the rules; `apply` persists one action.
use axum::http::StatusCode;
use chrono::{DateTime, Duration, Utc};
use sea_orm::{
    sea_query::Expr, ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter,
    Set, TransactionTrait,
};
use uuid::Uuid;

use crate::{
    api_error::ApiError,
    models::{
        _entities::{finding_events, findings},
        audit,
    },
};

pub const ACCEPT_DEFAULT: Duration = Duration::days(90);
pub const ACCEPT_MAX: Duration = Duration::days(365);
pub const SNOOZE_MAX: Duration = Duration::days(30);
const REASON_MAX: usize = 1000;

#[derive(Debug, Clone)]
pub enum Action {
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
pub struct Change {
    pub status: &'static str,
    pub event: &'static str,
    pub accepted_reason: Option<String>,
    pub accepted_until: Option<DateTime<Utc>>,
    pub snoozed_until: Option<DateTime<Utc>>,
}

fn until_within(until: DateTime<Utc>, now: DateTime<Utc>, max: Duration) -> Result<(), ApiError> {
    if until <= now {
        return Err(ApiError::invalid("until must be in the future"));
    }
    if until > now + max {
        return Err(ApiError::invalid(format!(
            "until must be at most {} days ahead",
            max.num_days()
        )));
    }
    Ok(())
}

pub fn decide(status: &str, action: Action, now: DateTime<Utc>) -> Result<Change, ApiError> {
    if status == "resolved" {
        return Err(ApiError::invalid("the finding is resolved"));
    }
    let none = Change {
        status: "open",
        event: "reopened",
        accepted_reason: None,
        accepted_until: None,
        snoozed_until: None,
    };
    match action {
        Action::Accept { reason, until } => {
            let reason = reason.as_deref().map(str::trim).unwrap_or_default();
            if reason.is_empty() || reason.chars().count() > REASON_MAX {
                return Err(ApiError::invalid(format!(
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
        Action::Snooze { until } => {
            until_within(until, now, SNOOZE_MAX)?;
            Ok(Change {
                status: "snoozed",
                event: "snoozed",
                snoozed_until: Some(until),
                ..none
            })
        }
        Action::Reopen if matches!(status, "accepted" | "snoozed") => Ok(none),
        Action::Reopen => Err(ApiError::invalid(
            "only accepted or snoozed findings reopen",
        )),
    }
}

// shortcut: ~57 lines, mostly the column list of one CAS update; split if the action set grows.
/// Applies `action` to `f` for `actor`: status compare-and-set, event and audit row, one
/// transaction. Returns the updated finding.
pub async fn apply(
    db: &DatabaseConnection,
    f: &findings::Model,
    actor: Uuid,
    action: Action,
    now: DateTime<Utc>,
) -> Result<findings::Model, ApiError> {
    let c = decide(&f.status, action, now)?;
    let txn = db.begin().await?;
    let updated = findings::Entity::update_many()
        .col_expr(findings::Column::Status, Expr::value(c.status))
        .col_expr(
            findings::Column::AcceptedReason,
            Expr::value(c.accepted_reason),
        )
        .col_expr(
            findings::Column::AcceptedUntil,
            Expr::value(c.accepted_until),
        )
        .col_expr(findings::Column::SnoozedUntil, Expr::value(c.snoozed_until))
        .col_expr(findings::Column::UpdatedAt, Expr::value(now))
        .filter(findings::Column::OrganisationId.eq(f.organisation_id))
        .filter(findings::Column::Id.eq(f.id))
        .filter(findings::Column::Status.eq(f.status.as_str()))
        .exec_with_returning(&txn)
        .await?
        .pop()
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::CONFLICT,
                "finding_state_changed",
                "The finding changed while this request ran. Reload and try again.",
            )
        })?;
    finding_events::ActiveModel {
        id: Set(Uuid::now_v7()),
        finding_id: Set(f.id),
        run_id: Set(None),
        event_type: Set(c.event.into()),
        from_severity: Set(Some(f.severity.clone())),
        to_severity: Set(Some(f.severity.clone())),
        created_at: Set(now.into()),
        updated_at: Set(now.into()),
    }
    .insert(&txn)
    .await?;
    audit::record(
        &txn,
        Some(f.organisation_id),
        actor,
        &format!("finding.{}", c.event),
        Some(("finding", f.id.to_string())),
    )
    .await?;
    txn.commit().await?;
    Ok(updated)
}

const NOTE_MAX: usize = 2000;

/// Records a customer report that an explanation is wrong (audit row with the note).
pub async fn report_explanation(
    db: &DatabaseConnection,
    f: &findings::Model,
    actor: Uuid,
    note: &str,
) -> Result<(), ApiError> {
    let note = note.trim();
    if note.is_empty() || note.chars().count() > NOTE_MAX {
        return Err(ApiError::invalid(format!(
            "note is required (at most {NOTE_MAX} characters)"
        )));
    }
    audit::record_meta(
        db,
        Some(f.organisation_id),
        actor,
        "finding.report_explanation",
        Some(("finding", f.id.to_string())),
        serde_json::json!({ "note": note }),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        "2026-10-22T12:00:00Z".parse().unwrap()
    }

    fn accept(reason: Option<&str>, days: Option<i64>) -> Action {
        Action::Accept {
            reason: reason.map(Into::into),
            until: days.map(|d| now() + Duration::days(d)),
        }
    }

    fn snooze(days: i64) -> Action {
        Action::Snooze {
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
            let c = decide(s, Action::Reopen, now()).unwrap();
            assert_eq!(
                (c.status, c.event, c.snoozed_until),
                ("open", "reopened", None)
            );
        }
        for s in ["open", "flapping"] {
            assert!(decide(s, Action::Reopen, now()).is_err());
        }
    }

    #[test]
    fn resolved_findings_take_no_action() {
        assert!(decide("resolved", accept(Some("r"), None), now()).is_err());
        assert!(decide("resolved", snooze(1), now()).is_err());
    }
}
