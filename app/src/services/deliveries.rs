//! Delivery reads the workers share: the briefing window and document, the route, and
//! connection housekeeping. Rows live in the deliveries repository, keyed by (run, effect
//! key), so a resumed run rewrites its own rows instead of adding more.
use std::time::Duration;

use chrono::{DateTime, Utc};
use opsagent_core::{connection::ConnectionStatus, org::OrganisationsRepo, repo::RepoResult};
use opsagent_deliver::{
    briefing::build_briefing,
    model::Briefing,
    repo::{DeliveriesRepo, RecipientsRepo},
    route::{resolve, Route},
};
use opsagent_ledger::{ChunkOutcome, LedgerError, RunChunkedOptions, RunRow};
use sea_orm::{ColumnTrait, ConnectionTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter};
use serde_json::json;
use uuid::Uuid;

pub use opsagent_deliver::repo::{BRIEFING, FAILED, FALLBACK_EMAIL, SENT, SUPPRESSED, WEEKLY};

use crate::{
    adapters::db::Pg,
    models::{_entities::connections, connections::status_of, ledger_storage::stmt},
    workers::common::{lerr, LResult},
};

const LEASE_TTL: Duration = Duration::from_secs(60);

/// Start of the briefing window: the last briefing sent (to Slack or as the email fallback)
/// before `before` (the run's slot, so a resumed run never counts its own rows), else the
/// connection's creation.
pub async fn since(
    db: &impl ConnectionTrait,
    c: &connections::Model,
    before: DateTime<Utc>,
) -> RepoResult<DateTime<Utc>> {
    let last = Pg::new(db)
        .last_success_at(c.organisation_id, c.id, BRIEFING, before)
        .await?;
    Ok(last.unwrap_or_else(|| c.created_at.to_utc()))
}

/// The briefing for `c` at `now`, for the window ending at `before`; `None`: nothing to say.
pub async fn briefing(
    db: &impl ConnectionTrait,
    c: &connections::Model,
    before: DateTime<Utc>,
    now: DateTime<Utc>,
    link_base: &str,
) -> RepoResult<Option<Briefing>> {
    let since = since(db, c, before).await?;
    let repo = Pg::new(db);
    let conn = repo.connection_snapshot(c.organisation_id, c.id).await?;
    let findings = repo
        .finding_snapshots(c.organisation_id, c.id, since)
        .await?;
    Ok(build_briefing(&conn, &findings, since, now, link_base))
}

/// Where `c`'s deliveries go. The Slack channel counts only while Slack is connected (a
/// revoked integration is skipped until the owner reconnects); the organisation has no
/// channel of its own.
pub async fn route(
    db: &impl ConnectionTrait,
    c: &connections::Model,
    slack_active: bool,
) -> RepoResult<Route> {
    let repo = Pg::new(db);
    let conn = Route {
        slack_channel: c.slack_channel_id.clone().filter(|_| slack_active),
        recipients: repo.for_connection(c.organisation_id, Some(c.id)).await?,
    };
    let org = Route {
        slack_channel: None,
        recipients: repo.for_connection(c.organisation_id, None).await?,
    };
    Ok(resolve(Some(conn), org))
}

/// The channel was archived or deleted: clear it from the connection (if still set to it).
pub async fn clear_channel(
    db: &impl ConnectionTrait,
    c: &connections::Model,
    channel: &str,
) -> Result<(), DbErr> {
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
