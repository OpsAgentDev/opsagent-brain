//! Finding lifecycle per `full_scan` (PRD 7.4): open, seen, escalate, resolve, reopen, flap.
//! Re-applying the same run is a no-op: findings already stamped with the run are skipped and
//! events are unique per (run, finding, type).
use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::{DateTime, Duration, Utc};
use opsagent_core::finding::{FindingDraft, Severity};
use opsagent_ledger::{LedgerError, Result};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Value};
use serde_json::{json, Value as Json};
use uuid::Uuid;

use super::{inventory_upsert::exec, redact::redact};
use crate::models::{
    _entities::{connections, findings},
    enum_of, enum_str,
    ledger_storage::{db_err, stmt},
};

const FLAP_WINDOW: Duration = Duration::hours(24);
const FLAP_SPAN: Duration = Duration::days(7);
const FLAP_TIMES: i32 = 3;
const EVIDENCE_TTL: Duration = Duration::days(90);
/// Consecutive seen runs after which a flapping finding counts as stable again.
const STABLE_RUNS: i32 = 7;

type Key = (String, String, String);

fn key_of(f: &findings::Model) -> Key {
    (
        f.check_id.clone(),
        f.resource_identity.clone(),
        f.variant.clone(),
    )
}

/// Applies one run's drafts. `partial`: the inventory was incomplete, so nothing is resolved.
pub async fn apply(
    db: &impl ConnectionTrait,
    c: &connections::Model,
    run_id: Uuid,
    drafts: &[FindingDraft],
    now: DateTime<Utc>,
    partial: bool,
) -> Result<()> {
    let existing: HashMap<Key, findings::Model> = findings::Entity::find()
        .filter(findings::Column::OrganisationId.eq(c.organisation_id))
        .filter(findings::Column::ConnectionId.eq(c.id))
        .all(db)
        .await
        .map_err(db_err)?
        .into_iter()
        .map(|f| (key_of(&f), f))
        .collect();
    let mut seen = HashSet::new();
    for d in &dedupe(drafts) {
        let k = (
            d.key.check_id.clone(),
            d.key.resource_identity.clone(),
            d.key.variant.clone(),
        );
        seen.insert(k.clone());
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
    if partial {
        return Ok(());
    }
    for f in existing.values() {
        if seen.contains(&key_of(f)) || !matches!(f.status.as_str(), "open" | "flapping") {
            continue;
        }
        resolve(db, f, run_id, now).await?;
    }
    Ok(())
}

/// One draft per key (checks may emit a key twice): highest severity wins, evidence merges.
fn dedupe(drafts: &[FindingDraft]) -> Vec<FindingDraft> {
    let mut out: Vec<FindingDraft> = Vec::with_capacity(drafts.len());
    for d in drafts {
        match out.iter_mut().find(|o| o.key == d.key) {
            Some(o) => {
                let mut evidence = std::mem::take(&mut o.evidence);
                evidence.extend(d.evidence.iter().cloned());
                if d.severity.weight() > o.severity.weight() {
                    *o = d.clone();
                }
                o.evidence = evidence;
            }
            None => out.push(d.clone()),
        }
    }
    out
}

async fn insert(
    db: &impl ConnectionTrait,
    c: &connections::Model,
    run_id: Uuid,
    d: &FindingDraft,
) -> Result<Uuid> {
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

async fn seen_again(
    db: &impl ConnectionTrait,
    f: &findings::Model,
    run_id: Uuid,
    d: &FindingDraft,
    now: DateTime<Utc>,
) -> Result<()> {
    let expired = |until: Option<sea_orm::prelude::DateTimeWithTimeZone>| {
        until.is_some_and(|u| u.with_timezone(&Utc) <= now)
    };
    let mut flap_count = f.flap_count;
    let mut stable = f.stable_runs + 1;
    let mut events: Vec<&str> = vec![];
    let status = match f.status.as_str() {
        "open" => {
            events.push("seen");
            "open"
        }
        "flapping" if stable >= STABLE_RUNS => {
            flap_count = 0;
            events.push("reopened");
            "open"
        }
        // Reported once when it started flapping; afterwards only counters move.
        "flapping" => "flapping",
        "accepted" if expired(f.accepted_until) => {
            events.push("reopened");
            "open"
        }
        "snoozed" if expired(f.snoozed_until) => {
            events.push("reopened");
            "open"
        }
        "accepted" | "snoozed" => f.status.as_str(),
        _ => {
            stable = 1;
            let quick = f
                .resolved_at
                .is_some_and(|r| now - r.with_timezone(&Utc) <= FLAP_WINDOW);
            flap_count += i32::from(quick);
            if flap_count >= FLAP_TIMES && count_events(db, f.id, "flapping", now).await? > 0 {
                "flapping"
            } else if quick
                && flap_count >= FLAP_TIMES
                && count_events(db, f.id, "reopened", now).await? + 1 >= i64::from(FLAP_TIMES)
            {
                events.extend(["reopened", "flapping"]);
                "flapping"
            } else {
                events.push("reopened");
                "open"
            }
        }
    };
    exec(
        db,
        "UPDATE findings SET status = $2, severity = $3, title = $4, summary = $5, next_step = $6, \
         cost_monthly_usd = $7, last_seen_run_id = $8, flap_count = $9, stable_runs = $10, resolved_at = NULL, \
         resolved_reason = NULL, updated_at = now() WHERE id = $1 AND organisation_id = $11",
        vec![
            f.id.into(),
            status.into(),
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

async fn resolve(
    db: &impl ConnectionTrait,
    f: &findings::Model,
    run_id: Uuid,
    now: DateTime<Utc>,
) -> Result<()> {
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
        "UPDATE findings SET status = 'resolved', resolved_at = $2, resolved_reason = $3, stable_runs = 0, \
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
) -> Result<i64> {
    let r = db
        .query_one_raw(stmt(
            "SELECT count(*) AS n FROM finding_events WHERE finding_id = $1 AND event_type = $2 AND created_at > $3",
            vec![finding_id.into(), kind.into(), (now - FLAP_SPAN).into()],
        ))
        .await
        .map_err(db_err)?
        .ok_or(LedgerError::NotFound)?;
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
) -> Result<()> {
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
) -> Result<()> {
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

/// Posture score per checks.md: `max(0, 100 − Σ weight(open))`; accepted, snoozed and flapping
/// are excluded by counting `open` only.
pub async fn posture(db: &impl ConnectionTrait, c: &connections::Model) -> Result<Json> {
    let rows = db
        .query_all_raw(stmt(
            "SELECT severity, count(*) AS n FROM findings WHERE organisation_id = $2 AND connection_id = $1 \
             AND status = 'open' GROUP BY severity",
            vec![Value::from(c.id), Value::from(c.organisation_id)],
        ))
        .await
        .map_err(db_err)?;
    let mut counts: BTreeMap<String, i64> = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ]
    .into_iter()
    .map(|s| (enum_str(s), 0))
    .collect();
    let mut sum = 0f32;
    for r in rows {
        let s: String = r.try_get("", "severity").map_err(db_err)?;
        let n: i64 = r.try_get("", "n").map_err(db_err)?;
        sum += enum_of(&s).map_or(0.0, Severity::weight) * n as f32;
        counts.insert(s, n);
    }
    Ok(json!({ "score": f64::from((100.0 - sum).max(0.0)), "counts_by_severity": counts }))
}
