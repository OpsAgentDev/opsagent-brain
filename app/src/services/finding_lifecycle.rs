//! Finding lifecycle per `full_scan` (PRD 7.4). The repository upserts what the run saw and
//! resolves what it did not; this holds the rule of which checks may resolve.
use chrono::{DateTime, Utc};
use opsagent_core::finding::{FindingDraft, FindingsRepo};
use opsagent_ledger::Result;
use sea_orm::DatabaseTransaction;
use uuid::Uuid;

use crate::{
    adapters::db::Pg,
    models::{_entities::connections, ledger_storage::db_err},
};

/// Applies one run's drafts. `check_ids`: the checks of this scan. `partial`: the inventory
/// was incomplete, so nothing is resolved.
pub async fn apply(
    txn: &DatabaseTransaction,
    c: &connections::Model,
    run_id: Uuid,
    drafts: &[FindingDraft],
    now: DateTime<Utc>,
    partial: bool,
    check_ids: &[String],
) -> Result<()> {
    let repo = Pg::new(txn);
    let (org, conn) = (c.organisation_id, c.id);
    repo.upsert_seen(org, conn, run_id, drafts, now)
        .await
        .map_err(db_err)?;
    let resolvable = if partial { &[][..] } else { check_ids };
    repo.resolve_unseen(org, conn, run_id, resolvable, now)
        .await
        .map_err(db_err)?;
    Ok(())
}
