//! Finding lifecycle per `full_scan` (PRD 7.4). The repository upserts what the run saw and
//! resolves what it did not; this holds the rule of which findings may resolve.
use chrono::{DateTime, Utc};
use opsagent_core::finding::{FindingDraft, FindingsRepo};
use opsagent_ledger::Result;
use sea_orm::DatabaseTransaction;
use uuid::Uuid;

use crate::{
    adapters::db::{ledger_storage::db_err, Pg},
    models::_entities::connections,
};

/// Applies one run's drafts. Every unseen finding resolves, except those of checks whose
/// capability was partial. `partial` is run-wide today (every check counts as partial), so a
/// partial run resolves nothing.
pub async fn apply(
    txn: &DatabaseTransaction,
    c: &connections::Model,
    run_id: Uuid,
    drafts: &[FindingDraft],
    now: DateTime<Utc>,
    partial: bool,
) -> Result<()> {
    let repo = Pg::new(txn);
    let (org, conn) = (c.organisation_id, c.id);
    repo.upsert_seen(org, conn, run_id, drafts, now)
        .await
        .map_err(db_err)?;
    if partial {
        return Ok(());
    }
    repo.resolve_unseen(org, conn, run_id, &[], now)
        .await
        .map_err(db_err)?;
    Ok(())
}
