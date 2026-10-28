//! Persisting the lifecycle of findings seen in a run (PRD 7.4): open, seen, escalate, resolve,
//! reopen, flap; the transition rules are `opsagent_core::lifecycle`. Re-applying the same run
//! is a no-op: findings already stamped with the run are skipped and events are unique per
//! (run, finding, type).
use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use opsagent_core::{
    finding::{dedupe, FindingDraft, Severity},
    lifecycle::{Next, RecentEvents, SeenFinding, FLAP_SPAN},
    repo::RepoResult,
};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use uuid::Uuid;

use super::{exec, Target};
use crate::{
    adapters::db::db_err,
    adapters::db::ledger_storage::stmt,
    adapters::redact::redact,
    models::{_entities::findings, enum_of, enum_str},
};

const EVIDENCE_TTL: Duration = Duration::days(90);

type Key = (String, String, String);

fn key_of(f: &findings::Model) -> Key {
    (
        f.check_id.clone(),
        f.resource_identity.clone(),
        f.variant.clone(),
    )
}

/// Upserts one run's drafts (the lifecycle of seen findings); resolving is `resolve_unseen`.
pub(super) async fn upsert_seen(
    db: &impl ConnectionTrait,
    c: Target,
    run_id: Uuid,
    drafts: &[FindingDraft],
    now: DateTime<Utc>,
) -> RepoResult<()> {
    let existing: HashMap<Key, findings::Model> = findings::Entity::find()
        .filter(findings::Column::OrganisationId.eq(c.organisation_id))
        .filter(findings::Column::ConnectionId.eq(c.id))
        .all(db)
        .await
        .map_err(db_err)?
        .into_iter()
        .map(|f| (key_of(&f), f))
        .collect();
    for d in &dedupe(drafts) {
        let k = (
            d.key.check_id.clone(),
            d.key.resource_identity.clone(),
            d.key.variant.clone(),
        );
        let id = match existing.get(&k) {
            None => {
                let id = insert(db, c, run_id, d).await?;
                event(db, id, run_id, "opened", None, Some(d.severity), now).await?;
                id
            }
            Some(f) if f.last_seen_run_id == Some(run_id) => continue,
            Some(f) => {
                seen_again(db, f, run_id, d, now).await?;
                f.id
            }
        };
        evidence(db, id, run_id, d, now).await?;
    }
    Ok(())
}

async fn insert(
    db: &impl ConnectionTrait,
    c: Target,
    run_id: Uuid,
    d: &FindingDraft,
) -> RepoResult<Uuid> {
    let id = Uuid::now_v7();
    exec(
        db,
        "INSERT INTO findings (id, organisation_id, connection_id, check_id, resource_identity, variant, \
         severity, status, title, summary, next_step, cost_monthly_usd, first_seen_run_id, last_seen_run_id) \
         VALUES ($1, $12, $2, $3, $4, $5, $6, 'open', $7, $8, $9, $10, $11, $11)",
        vec![
            id.into(),
            c.id.into(),
            d.key.check_id.clone().into(),
            d.key.resource_identity.clone().into(),
            d.key.variant.clone().into(),
            enum_str(d.severity).into(),
            d.title.clone().into(),
            d.summary.clone().into(),
            d.next_step.clone().into(),
            d.cost_monthly_usd.into(),
            run_id.into(),
            c.organisation_id.into(),
        ],
    )
    .await?;
    Ok(id)
}

/// The stored state as the PRD 7.4 rules read it, plus the recent events they need.
async fn next_state(
    db: &impl ConnectionTrait,
    f: &findings::Model,
    now: DateTime<Utc>,
) -> RepoResult<Next> {
    let utc = |t: Option<sea_orm::prelude::DateTimeWithTimeZone>| t.map(|t| t.with_timezone(&Utc));
    let seen = SeenFinding {
        status: &f.status,
        flap_count: f.flap_count,
        stable_runs: f.stable_runs,
        accepted_until: utc(f.accepted_until),
        snoozed_until: utc(f.snoozed_until),
        resolved_at: utc(f.resolved_at),
    };
    let recent = if seen.reappears() {
        RecentEvents {
            flapping: count_events(db, f.id, "flapping", now).await?,
            reopened: count_events(db, f.id, "reopened", now).await?,
        }
    } else {
        RecentEvents::default()
    };
    Ok(seen.next(recent, now))
}

async fn seen_again(
    db: &impl ConnectionTrait,
    f: &findings::Model,
    run_id: Uuid,
    d: &FindingDraft,
    now: DateTime<Utc>,
) -> RepoResult<()> {
    let Next {
        status,
        events,
        flap_count,
        stable,
    } = next_state(db, f, now).await?;
    exec(
        db,
        "UPDATE findings SET status = $2, severity = $3, title = $4, summary = $5, next_step = $6, \
         cost_monthly_usd = $7, last_seen_run_id = $8, flap_count = $9, stable_runs = $10, resolved_at = NULL, \
         resolved_reason = NULL, updated_at = now() WHERE id = $1 AND organisation_id = $11",
        vec![
            f.id.into(),
            status.clone().into(),
            enum_str(d.severity).into(),
            d.title.clone().into(),
            d.summary.clone().into(),
            d.next_step.clone().into(),
            d.cost_monthly_usd.into(),
            run_id.into(),
            flap_count.into(),
            stable.into(),
            f.organisation_id.into(),
        ],
    )
    .await?;
    let from = enum_of(&f.severity);
    for e in events {
        event(db, f.id, run_id, e, from, Some(d.severity), now).await?;
    }
    if status == "open" && f.status == "open" {
        if let Some(from) = from.filter(|s| *s != d.severity) {
            let e = if d.severity.weight() > from.weight() {
                "escalated"
            } else {
                "deescalated"
            };
            event(db, f.id, run_id, e, Some(from), Some(d.severity), now).await?;
        }
    }
    Ok(())
}

pub(super) async fn resolve(
    db: &impl ConnectionTrait,
    f: &findings::Model,
    run_id: Uuid,
    now: DateTime<Utc>,
) -> RepoResult<()> {
    let gone = db
        .query_one_raw(stmt(
            "SELECT 1 FROM resources WHERE organisation_id = $3 AND connection_id = $1 AND identity = $2 \
             AND gone_at IS NOT NULL",
            vec![
                f.connection_id.into(),
                f.resource_identity.clone().into(),
                f.organisation_id.into(),
            ],
        ))
        .await
        .map_err(db_err)?
        .is_some();
    let reason = if gone {
        "resource_gone"
    } else {
        "check_passed"
    };
    exec(
        db,
        "UPDATE findings SET status = 'resolved', resolved_at = $2, resolved_reason = $3, stable_runs = 0, alerted_at = NULL, \
         updated_at = now() WHERE id = $1 AND organisation_id = $4",
        vec![f.id.into(), now.into(), reason.into(), f.organisation_id.into()],
    )
    .await?;
    if f.status != "flapping" {
        let s = enum_of(&f.severity);
        event(db, f.id, run_id, "resolved", s, s, now).await?;
    }
    Ok(())
}

/// Events of `kind` for the finding within the flap span.
async fn count_events(
    db: &impl ConnectionTrait,
    finding_id: Uuid,
    kind: &str,
    now: DateTime<Utc>,
) -> RepoResult<i64> {
    let r = db
        .query_one_raw(stmt(
            "SELECT count(*) AS n FROM finding_events WHERE finding_id = $1 AND event_type = $2 AND created_at > $3",
            vec![finding_id.into(), kind.into(), (now - FLAP_SPAN).into()],
        ))
        .await
        .map_err(db_err)?
        .ok_or_else(|| db_err("count returned no row"))?;
    r.try_get("", "n").map_err(db_err)
}

async fn event(
    db: &impl ConnectionTrait,
    finding_id: Uuid,
    run_id: Uuid,
    kind: &str,
    from: Option<Severity>,
    to: Option<Severity>,
    now: DateTime<Utc>,
) -> RepoResult<()> {
    exec(
        db,
        "INSERT INTO finding_events (id, finding_id, run_id, event_type, from_severity, to_severity, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (run_id, finding_id, event_type) DO NOTHING",
        vec![
            Uuid::now_v7().into(),
            finding_id.into(),
            run_id.into(),
            kind.into(),
            from.map(enum_str).into(),
            to.map(enum_str).into(),
            now.into(),
        ],
    )
    .await
}

/// Replaces this run's evidence for the finding, redacted.
async fn evidence(
    db: &impl ConnectionTrait,
    finding_id: Uuid,
    run_id: Uuid,
    d: &FindingDraft,
    now: DateTime<Utc>,
) -> RepoResult<()> {
    exec(
        db,
        "DELETE FROM evidence WHERE finding_id = $1 AND run_id = $2",
        vec![finding_id.into(), run_id.into()],
    )
    .await?;
    for e in &d.evidence {
        let (source, a) = redact(&e.source);
        let (excerpt, b) = redact(&e.excerpt);
        exec(
            db,
            "INSERT INTO evidence (id, finding_id, run_id, source, excerpt, redacted, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            vec![
                Uuid::now_v7().into(),
                finding_id.into(),
                run_id.into(),
                source.into(),
                excerpt.into(),
                (a || b).into(),
                (now + EVIDENCE_TTL).into(),
            ],
        )
        .await?;
    }
    Ok(())
}
