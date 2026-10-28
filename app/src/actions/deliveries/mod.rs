//! Deliveries (delivery.md): the history, the briefing preview, and the briefing and weekly
//! jobs and urgent alerts, each mail through `MailGuard` and each send once per run and effect key.
mod deliver_alert;
mod deliver_briefing;
mod deliver_weekly;
mod delivery_out;
mod get_delivery;
mod list_deliveries;
mod preview_briefing;
mod snapshots;

use std::{sync::Arc, time::Duration};

use opsagent_core::repo::{Clock, RepoResult};
use opsagent_deliver::repo::DeliveryRow;
use opsagent_ledger::{redis, ChunkOutcome, RunChunkedOptions};
use opsagent_secrets::Kek;
use serde_json::json;
use uuid::Uuid;

pub use deliver_alert::DeliverAlert;
pub use deliver_briefing::{DeliverBriefing, DeliverBriefingNow};
pub use deliver_weekly::DeliverWeekly;
pub use get_delivery::GetDelivery;
pub use list_deliveries::ListDeliveries;
pub use preview_briefing::{Preview, PreviewBriefing};

use super::{recipients::MailGuard, uow::Repos, uow::UnitOfWork};
use crate::{adapters::slack::SlackClient, mailers::Mailer};

const LEASE_TTL: Duration = Duration::from_secs(60);

pub struct Deliveries {
    pub list_deliveries: ListDeliveries,
    pub get_delivery: GetDelivery,
    pub preview_briefing: PreviewBriefing,
    pub deliver_briefing: DeliverBriefing,
    pub deliver_weekly: DeliverWeekly,
    pub deliver_alert: DeliverAlert,
    pub deliver_briefing_now: DeliverBriefingNow,
}

/// What the delivery jobs send with.
#[derive(Clone)]
pub struct Kit {
    pub uow: Arc<dyn UnitOfWork>,
    /// Leases (`opsagent_ledger::lease`).
    pub redis: redis::Client,
    pub kek: Arc<dyn Kek>,
    pub mailer: Arc<dyn Mailer>,
    pub slack: Arc<dyn SlackClient>,
    pub guard: Arc<MailGuard>,
    pub clock: Arc<dyn Clock>,
    /// Base of the links in briefings and digests.
    pub web_base_url: String,
    /// `Config::unsubscribe_key`, for unsubscribe links in the weekly digest.
    pub unsubscribe_key: String,
}

/// A delivery row with the id of the recipient it went to (email rows only; owner fallback
/// sends have no recipient row).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryItem {
    pub row: DeliveryRow,
    pub recipient_id: Option<Uuid>,
}

/// Recipient addresses never leave the server: email rows get their recipient's id instead.
async fn with_recipients(
    r: &dyn Repos,
    organisation_id: Uuid,
    rows: Vec<DeliveryRow>,
) -> RepoResult<Vec<DeliveryItem>> {
    let emails: Vec<String> = rows
        .iter()
        .filter(|d| d.channel == "email")
        .map(|d| d.target.to_lowercase())
        .collect();
    let ids = r
        .recipients()
        .ids_by_email(organisation_id, &emails)
        .await?;
    Ok(rows
        .into_iter()
        .map(|row| DeliveryItem {
            recipient_id: (row.channel == "email")
                .then(|| ids.get(&row.target.to_lowercase()).copied())
                .flatten(),
            row,
        })
        .collect())
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
fn outcome(key: &str, value: &str) -> ChunkOutcome {
    ChunkOutcome {
        stats: json!({ key: value }),
        ..Default::default()
    }
}
