//! Delivery reads and writes: the snapshots the `deliver` crate builds documents from, routes,
//! owners, and `deliveries` rows. Rows are keyed by (run, effect key), so a resumed run
//! rewrites its own rows instead of adding more.
use crate::adapters::db::ledger_storage::stmt;
use std::time::Duration;

use chrono::{DateTime, Utc};
use opsagent_core::org::OrganisationsRepo;
use opsagent_core::{
    connection::ConnectionStatus,
    finding::{FindingKey, Severity},
};
use opsagent_deliver::{
    briefing::build_briefing,
    model::{
        Briefing, ConnectionSnapshot, EventKind, FindingSnapshot, FindingStatus, SeverityCounts,
    },
    route::{resolve, Recipient, Route},
};
use opsagent_ledger::{ChunkOutcome, LedgerError, RunChunkedOptions, RunRow};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter, QueryResult,
    Value,
};
use serde_json::json;
use uuid::Uuid;

use crate::{
    adapters::db::{status_of, Pg},
    models::{
        _entities::{connections, integrations},
        enum_of,
        integrations::{ACTIVE, SLACK},
    },
    services::posture::posture,
    workers::common::{lerr, LResult},
};

pub const BRIEFING: &str = "briefing";
pub const WEEKLY: &str = "weekly";
pub const SENT: &str = "sent";
pub const FAILED: &str = "failed";
pub const FALLBACK_EMAIL: &str = "fallback_email";
pub const SUPPRESSED: &str = "suppressed";

const LEASE_TTL: Duration = Duration::from_secs(60);

type DbResult<T> = Result<T, DbErr>;

fn ts(r: &QueryResult, col: &str) -> DbResult<Option<DateTime<Utc>>> {
    Ok(
        r.try_get::<Option<sea_orm::prelude::DateTimeWithTimeZone>>("", col)?
            .map(|t| t.to_utc()),
    )
}

/// Start of the briefing window: the last briefing sent (to Slack or as the email fallback)
/// before `before` (the run's slot, so a resumed run never counts its own rows), else the
/// connection's creation.
pub async fn since(
    db: &impl ConnectionTrait,
    c: &connections::Model,
    before: DateTime<Utc>,
) -> DbResult<DateTime<Utc>> {
    let row = db
        .query_one_raw(stmt(
            "SELECT max(sent_at) AS t FROM deliveries WHERE organisation_id = $1 \
             AND connection_id = $2 AND kind = 'briefing' AND status IN ('sent','fallback_email') \
             AND sent_at < $3",
            vec![c.organisation_id.into(), c.id.into(), before.into()],
        ))
        .await?;
    let last = match row {
        Some(r) => ts(&r, "t")?,
        None => None,
    };
    Ok(last.unwrap_or_else(|| c.created_at.to_utc()))
}

/// The connection's state now: live finding counts, score, and its full scans.
pub async fn connection_snapshot(
    db: &impl ConnectionTrait,
    c: &connections::Model,
) -> DbResult<ConnectionSnapshot> {
    let ids = || vec![Value::from(c.organisation_id), Value::from(c.id)];
    let mut counts = SeverityCounts::default();
    for r in db
        .query_all_raw(stmt(
            "SELECT severity, count(*) AS n FROM findings WHERE organisation_id = $1 \
             AND connection_id = $2 AND status IN ('open','flapping') GROUP BY severity",
            ids(),
        ))
        .await?
    {
        let n = u32::try_from(r.try_get::<i64>("", "n")?).unwrap_or(u32::MAX);
        match enum_of::<Severity>(&r.try_get::<String>("", "severity")?) {
            Some(Severity::Critical) => counts.critical = n,
            Some(Severity::High) => counts.high = n,
            Some(Severity::Medium) => counts.medium = n,
            Some(Severity::Low) => counts.low = n,
            Some(Severity::Info) => counts.info = n,
            None => {}
        }
    }
    let scans = db
        .query_one_raw(stmt(
            "SELECT min(finished_at) AS first, max(finished_at) AS last, \
             (array_agg(status ORDER BY finished_at DESC))[1] AS latest FROM runs \
             WHERE organisation_id = $1 AND connection_id = $2 AND job_type = 'full_scan' \
             AND status IN ('done','partial') AND finished_at IS NOT NULL",
            ids(),
        ))
        .await?;
    let (first, last, latest) = match &scans {
        Some(r) => (
            ts(r, "first")?,
            ts(r, "last")?,
            r.try_get::<Option<String>>("", "latest")?,
        ),
        None => (None, None, None),
    };
    let score = posture(db, c)
        .await
        .map_err(|e| DbErr::Custom(e.to_string()))?["score"]
        .as_f64();
    Ok(ConnectionSnapshot {
        id: c.id,
        display_name: c.display_name.clone().unwrap_or_else(|| c.provider.clone()),
        status: status_of(c).map_err(|e| DbErr::Custom(e.to_string()))?,
        status_reason: c.status_reason.clone(),
        posture_score: score,
        // shortcut: no score history is stored yet; the weekly delta stays empty until it is.
        prev_posture_score: None,
        counts_by_severity: counts,
        first_scan_at: first,
        last_scan_at: last,
        partial: latest.as_deref() == Some("partial"),
    })
}

/// Live findings, plus any finding with an event since `since` (its events oldest first).
pub async fn finding_snapshots(
    db: &impl ConnectionTrait,
    c: &connections::Model,
    since: DateTime<Utc>,
) -> DbResult<Vec<FindingSnapshot>> {
    let rows = db
        .query_all_raw(stmt(
            "SELECT f.id, f.check_id, f.resource_identity, f.variant, f.severity, f.status, \
             f.title, f.cost_monthly_usd::float8 AS cost, f.created_at, f.updated_at, \
             coalesce(string_agg(e.event_type, ',' ORDER BY e.created_at), '') AS events \
             FROM findings f LEFT JOIN finding_events e ON e.finding_id = f.id AND e.created_at >= $3 \
             WHERE f.organisation_id = $1 AND f.connection_id = $2 GROUP BY f.id \
             HAVING f.status IN ('open','flapping') OR count(e.id) > 0",
            vec![c.organisation_id.into(), c.id.into(), since.into()],
        ))
        .await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let (Some(severity), Some(status)) = (
            enum_of::<Severity>(&r.try_get::<String>("", "severity")?),
            enum_of::<FindingStatus>(&r.try_get::<String>("", "status")?),
        ) else {
            continue;
        };
        let events: String = r.try_get("", "events")?;
        out.push(FindingSnapshot {
            id: r.try_get("", "id")?,
            key: FindingKey {
                connection_id: c.id,
                check_id: r.try_get("", "check_id")?,
                resource_identity: r.try_get("", "resource_identity")?,
                variant: r.try_get("", "variant")?,
            },
            severity,
            status,
            title: r.try_get("", "title")?,
            cost_monthly_usd: r.try_get("", "cost")?,
            first_seen_at: ts(&r, "created_at")?.unwrap_or_default(),
            last_seen_at: ts(&r, "updated_at")?.unwrap_or_default(),
            // Kinds the briefing does not use (accepted, snoozed) are dropped.
            events_since: events.split(',').filter_map(enum_of::<EventKind>).collect(),
        });
    }
    Ok(out)
}

/// The briefing for `c` at `now`, for the window ending at `before`; `None`: nothing to say.
pub async fn briefing(
    db: &impl ConnectionTrait,
    c: &connections::Model,
    before: DateTime<Utc>,
    now: DateTime<Utc>,
    link_base: &str,
) -> DbResult<Option<Briefing>> {
    let since = since(db, c, before).await?;
    let conn = connection_snapshot(db, c).await?;
    let findings = finding_snapshots(db, c, since).await?;
    Ok(build_briefing(&conn, &findings, since, now, link_base))
}

/// The organisation's active Slack integration.
pub async fn slack_integration(
    db: &impl ConnectionTrait,
    organisation_id: Uuid,
) -> DbResult<Option<integrations::Model>> {
    integrations::Entity::find()
        .filter(integrations::Column::OrganisationId.eq(organisation_id))
        .filter(integrations::Column::Kind.eq(SLACK))
        .filter(integrations::Column::Status.eq(ACTIVE))
        .one(db)
        .await
}

/// Active, subscribed recipients of the organisation (`connection` `None`) or a connection.
async fn recipients(
    db: &impl ConnectionTrait,
    organisation_id: Uuid,
    connection: Option<Uuid>,
) -> DbResult<Vec<Recipient>> {
    let rows = db
        .query_all_raw(stmt(
            "SELECT id, email, member_id IS NOT NULL AS member FROM recipients \
             WHERE organisation_id = $1 AND connection_id IS NOT DISTINCT FROM $2 \
             AND status = 'active' AND unsubscribed_at IS NULL ORDER BY created_at",
            vec![organisation_id.into(), connection.into()],
        ))
        .await?;
    rows.iter()
        .map(|r| {
            Ok(Recipient {
                id: r.try_get("", "id")?,
                email: r.try_get("", "email")?,
                member: r.try_get("", "member")?,
            })
        })
        .collect()
}

/// Where `c`'s deliveries go. The Slack channel counts only while Slack is connected (a
/// revoked integration is skipped until the owner reconnects); the organisation has no
/// channel of its own.
pub async fn route(
    db: &impl ConnectionTrait,
    c: &connections::Model,
    slack_active: bool,
) -> DbResult<Route> {
    let conn = Route {
        slack_channel: c.slack_channel_id.clone().filter(|_| slack_active),
        recipients: recipients(db, c.organisation_id, Some(c.id)).await?,
    };
    let org = Route {
        slack_channel: None,
        recipients: recipients(db, c.organisation_id, None).await?,
    };
    Ok(resolve(Some(conn), org))
}

/// The organisation's owners as member recipients (`id` is the user id).
pub async fn owners(db: &impl ConnectionTrait, organisation_id: Uuid) -> DbResult<Vec<Recipient>> {
    let rows = db
        .query_all_raw(stmt(
            "SELECT u.id, u.email FROM members m JOIN users u ON u.id = m.user_id \
             WHERE m.organisation_id = $1 AND m.role = 'owner' ORDER BY m.created_at",
            vec![organisation_id.into()],
        ))
        .await?;
    rows.iter()
        .map(|r| {
            Ok(Recipient {
                id: r.try_get("", "id")?,
                email: r.try_get::<String>("", "email")?.to_lowercase(),
                member: true,
            })
        })
        .collect()
}

/// One `deliveries` row.
pub struct Row<'a> {
    pub organisation_id: Uuid,
    pub connection_id: Option<Uuid>,
    pub kind: &'a str,
    pub channel: &'a str,
    pub target: &'a str,
    pub status: &'a str,
    pub external_ref: Option<String>,
}

/// Writes (or rewrites) the row for effect `key` of run `run_id`.
pub async fn record(
    db: &impl ConnectionTrait,
    run_id: Uuid,
    key: &str,
    row: Row<'_>,
) -> DbResult<()> {
    let id = Uuid::new_v5(&run_id, key.as_bytes());
    db.execute_raw(stmt(
        "INSERT INTO deliveries (id, organisation_id, connection_id, kind, channel, target, status, \
         external_ref, attempts, sent_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 1, \
         CASE WHEN $7 IN ('sent','fallback_email') THEN now() END) \
         ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status, \
         external_ref = coalesce(EXCLUDED.external_ref, deliveries.external_ref), \
         attempts = deliveries.attempts + 1, \
         sent_at = coalesce(deliveries.sent_at, EXCLUDED.sent_at), updated_at = now() \
         WHERE deliveries.organisation_id = EXCLUDED.organisation_id",
        vec![
            id.into(),
            row.organisation_id.into(),
            row.connection_id.into(),
            row.kind.into(),
            row.channel.into(),
            row.target.into(),
            row.status.into(),
            row.external_ref.into(),
        ],
    ))
    .await
    .map(|_| ())
}

/// Whether `c`'s briefing owes the one-time "Slack disconnected" notice: the organisation's
/// Slack integration is revoked and no briefing fell back to email for `c` between the
/// revocation (`integrations.updated_at`, set by `mark_revoked`) and `before` (the run's slot,
/// so a resumed run keeps the notice for every owner). Stored state, so it holds whichever
/// run (weekly, another connection's briefing) found the revocation.
pub async fn revoke_notice_due(
    db: &impl ConnectionTrait,
    c: &connections::Model,
    before: DateTime<Utc>,
) -> DbResult<bool> {
    let row = db
        .query_one_raw(stmt(
            "SELECT EXISTS (SELECT 1 FROM integrations i WHERE i.organisation_id = $1 \
             AND i.kind = 'slack' AND i.status = 'revoked' AND NOT EXISTS (SELECT 1 FROM \
             deliveries d WHERE d.organisation_id = $1 AND d.connection_id = $2 \
             AND d.kind = 'briefing' AND d.status = 'fallback_email' \
             AND d.sent_at >= i.updated_at AND d.sent_at < $3)) AS due",
            vec![c.organisation_id.into(), c.id.into(), before.into()],
        ))
        .await?;
    row.map_or(Ok(false), |r| r.try_get("", "due"))
}

/// Slack rejected the token: the integration is `revoked` until the owner reconnects.
pub async fn mark_revoked(db: &impl ConnectionTrait, i: &integrations::Model) -> DbResult<()> {
    db.execute_raw(stmt(
        "UPDATE integrations SET status = 'revoked', updated_at = now() \
         WHERE organisation_id = $1 AND id = $2",
        vec![i.organisation_id.into(), i.id.into()],
    ))
    .await
    .map(|_| ())
}

/// The channel was archived or deleted: clear it from the connection (if still set to it).
pub async fn clear_channel(
    db: &impl ConnectionTrait,
    c: &connections::Model,
    channel: &str,
) -> DbResult<()> {
    db.execute_raw(stmt(
        "UPDATE connections SET slack_channel_id = NULL, updated_at = now() \
         WHERE organisation_id = $1 AND id = $2 AND slack_channel_id = $3",
        vec![c.organisation_id.into(), c.id.into(), channel.into()],
    ))
    .await
    .map(|_| ())
}

/// Lease options for a delivery job.
pub fn options(job: &str) -> RunChunkedOptions {
    RunChunkedOptions {
        worker_id: format!("{job}-{}", Uuid::new_v4()),
        lease_ttl: LEASE_TTL,
        heartbeat_every: Duration::from_secs(20),
        ..Default::default()
    }
}

/// A chunk's outcome with the single stat `key: value`.
pub(crate) fn outcome(key: &str, value: &str) -> ChunkOutcome {
    ChunkOutcome {
        stats: json!({ key: value }),
        ..Default::default()
    }
}

/// The run's connection, or `None` when its organisation is deleted or it takes no deliveries.
pub(crate) async fn live_connection(
    db: &DatabaseConnection,
    run: &RunRow,
) -> LResult<Option<connections::Model>> {
    let id = run.key.connection_id.ok_or(LedgerError::NotFound)?;
    let c = connections::Entity::find_by_id(id)
        .filter(connections::Column::OrganisationId.eq(run.key.organisation_id))
        .one(db)
        .await
        .map_err(lerr)?
        .ok_or(LedgerError::NotFound)?;
    let gone = Pg::new(db)
        .is_deleted(c.organisation_id)
        .await
        .map_err(lerr)?;
    Ok((!gone && deliverable(&c)).then_some(c))
}

/// Whether a delivery for `c` makes sense: never-connected and disconnected connections get
/// none (a revoked or degraded one still does: its health is the news).
pub fn deliverable(c: &connections::Model) -> bool {
    matches!(
        status_of(c),
        Ok(ConnectionStatus::Connected | ConnectionStatus::Degraded | ConnectionStatus::Revoked)
    )
}
