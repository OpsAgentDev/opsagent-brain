//! The reads both delivery jobs and the preview share: the briefing window and document, the
//! route, and whether a run's connection still takes deliveries.
use chrono::{DateTime, Utc};
use opsagent_core::{
    connection::{Connection, ConnectionStatus},
    repo::RepoResult,
};
use opsagent_deliver::{
    briefing::build_briefing,
    model::Briefing,
    repo::BRIEFING,
    route::{resolve, Route},
};
use opsagent_ledger::{LedgerError, RunRow};

use crate::{
    actions::uow::Repos,
    workers::common::{lerr, LResult},
};

/// Start of the briefing window: the last briefing sent (to Slack or as the email fallback)
/// before `before` (the run's slot, so a resumed run never counts its own rows), else the
/// connection's creation.
async fn since(r: &dyn Repos, c: &Connection, before: DateTime<Utc>) -> RepoResult<DateTime<Utc>> {
    let last = r
        .deliveries()
        .last_success_at(c.organisation_id, c.id, BRIEFING, before)
        .await?;
    Ok(last.unwrap_or(c.created_at))
}

/// The briefing for `c` at `now`, for the window ending at `before`; `None`: nothing to say.
pub(super) async fn briefing(
    r: &dyn Repos,
    c: &Connection,
    before: DateTime<Utc>,
    now: DateTime<Utc>,
    link_base: &str,
) -> RepoResult<Option<Briefing>> {
    let since = since(r, c, before).await?;
    let d = r.deliveries();
    let conn = d.connection_snapshot(c.organisation_id, c.id).await?;
    let findings = d.finding_snapshots(c.organisation_id, c.id, since).await?;
    Ok(build_briefing(&conn, &findings, since, now, link_base))
}

/// Where `c`'s deliveries go. The Slack channel counts only while Slack is connected (a
/// revoked integration is skipped until the owner reconnects); the organisation has no
/// channel of its own.
pub(super) async fn route(r: &dyn Repos, c: &Connection, slack_active: bool) -> RepoResult<Route> {
    let conn = Route {
        slack_channel: c.slack_channel_id.clone().filter(|_| slack_active),
        recipients: r
            .recipients()
            .for_connection(c.organisation_id, Some(c.id))
            .await?,
    };
    let org = Route {
        slack_channel: None,
        recipients: r
            .recipients()
            .for_connection(c.organisation_id, None)
            .await?,
    };
    Ok(resolve(Some(conn), org))
}

/// The run's connection, or `None` when its organisation is deleted or it takes no deliveries.
pub(super) async fn live_connection(r: &dyn Repos, run: &RunRow) -> LResult<Option<Connection>> {
    let (Some(org), Some(id)) = (run.key.organisation_id, run.key.connection_id) else {
        return Err(LedgerError::NotFound);
    };
    let c = r
        .connections()
        .get(org, id)
        .await
        .map_err(lerr)?
        .ok_or(LedgerError::NotFound)?;
    let gone = r.orgs().is_deleted(org).await.map_err(lerr)?;
    Ok((!gone && deliverable(&c)).then_some(c))
}

/// Whether a delivery for `c` makes sense: never-connected and disconnected connections get
/// none (a revoked or degraded one still does: its health is the news).
pub(super) fn deliverable(c: &Connection) -> bool {
    matches!(
        c.status,
        ConnectionStatus::Connected | ConnectionStatus::Degraded | ConnectionStatus::Revoked
    )
}
