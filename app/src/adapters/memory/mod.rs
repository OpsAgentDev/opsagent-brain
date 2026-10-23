//! In-memory fakes of every repository, for tests. `begin` snapshots the whole state and
//! `commit` writes the snapshot back, so a dropped transaction leaves nothing behind.
mod audit;
mod connections;
mod deliveries;
mod findings;
mod integrations;
mod orgs;
mod rate_limiter;
mod recipients;
mod resources;
mod runs;
mod schedules;
mod users;

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    audit::{AuditEntry, AuditLog},
    connection::{Connection, ConnectionsRepo, SealedCreds},
    finding::FindingsRepo,
    org::{Invite, Organisation, OrganisationsRepo, Role},
    repo::{Cursor, PageOf, PageRequest, RepoResult},
    resource::ResourcesRepo,
    run::RunsRepo,
    user::{User, UsersRepo},
};
use opsagent_deliver::repo::{
    DeliveriesRepo, DeliveryRow, Integration, IntegrationsRepo, RecipientRow, RecipientsRepo,
    SchedulesRepo, Suppression,
};
use opsagent_ledger::Storage;
use uuid::Uuid;

pub use rate_limiter::MemRateLimiter;

/// A clock stopped at its time.
pub struct FixedClock(pub DateTime<Utc>);

impl opsagent_core::repo::Clock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}

use crate::actions::uow::{Repos, Tx, UnitOfWork};

#[derive(Clone)]
struct MemberRow {
    id: Uuid,
    organisation_id: Uuid,
    user_id: Uuid,
    role: Role,
    created_at: DateTime<Utc>,
}

#[derive(Clone)]
struct InviteRow {
    invite: Invite,
    token_hash: String,
    pending: bool,
}

#[derive(Clone)]
struct MagicLinkRow {
    user_id: Uuid,
    token_hash: String,
    expires_at: DateTime<Utc>,
    used: bool,
}

#[derive(Clone)]
struct MemRecipient {
    row: RecipientRow,
    confirm: Option<(String, DateTime<Utc>)>,
}

#[derive(Clone)]
struct SuppressionRow {
    organisation_id: Option<Uuid>,
    email_hash: String,
    kind: Suppression,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone)]
struct ScheduleRow {
    id: Uuid,
    organisation_id: Uuid,
    connection_id: Option<Uuid>,
    job_type: String,
    cron_local: String,
    timezone: String,
    next_due_at: Option<DateTime<Utc>>,
    enabled: bool,
}

#[derive(Clone, Default)]
pub struct MemState {
    orgs: Vec<Organisation>,
    members: Vec<MemberRow>,
    invites: Vec<InviteRow>,
    users: Vec<User>,
    magic_links: Vec<MagicLinkRow>,
    audit: Vec<AuditEntry>,
    connections: Vec<(Connection, SealedCreds)>,
    runs: Vec<runs::RunEntry>,
    /// `None`: started, `Some(external_ref)`: done.
    effects: HashMap<(Uuid, String), Option<Option<String>>>,
    findings: Vec<findings::FindingRow>,
    resources: Vec<resources::ResourceMem>,
    recipients: Vec<MemRecipient>,
    suppressions: Vec<SuppressionRow>,
    integrations: Vec<Integration>,
    deliveries: Vec<DeliveryRow>,
    schedules: Vec<ScheduleRow>,
}

#[derive(Clone, Default)]
pub struct MemStore(Arc<Mutex<MemState>>);

impl MemStore {
    fn state(&self) -> MutexGuard<'_, MemState> {
        // A panicking test poisons only itself; the state is still usable.
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl Repos for MemStore {
    fn orgs(&self) -> &dyn OrganisationsRepo {
        self
    }
    fn users(&self) -> &dyn UsersRepo {
        self
    }
    fn audit(&self) -> &dyn AuditLog {
        self
    }
    fn connections(&self) -> &dyn ConnectionsRepo {
        self
    }
    fn runs(&self) -> &dyn RunsRepo {
        self
    }
    fn ledger(&self) -> &dyn Storage {
        self
    }
    fn findings(&self) -> &dyn FindingsRepo {
        self
    }
    fn resources(&self) -> &dyn ResourcesRepo {
        self
    }
    fn recipients(&self) -> &dyn RecipientsRepo {
        self
    }
    fn integrations(&self) -> &dyn IntegrationsRepo {
        self
    }
    fn deliveries(&self) -> &dyn DeliveriesRepo {
        self
    }
    fn schedules(&self) -> &dyn SchedulesRepo {
        self
    }
}

#[async_trait]
impl UnitOfWork for MemStore {
    async fn begin(&self) -> RepoResult<Box<dyn Tx>> {
        // shortcut: single-threaded test support; concurrent transactions are not isolated and
        // the last commit wins. Use Pg for race and lock tests.
        let snapshot = self.state().clone();
        Ok(Box::new(MemTx {
            parent: self.clone(),
            work: MemStore(Arc::new(Mutex::new(snapshot))),
        }))
    }
}

struct MemTx {
    parent: MemStore,
    work: MemStore,
}

impl Repos for MemTx {
    fn orgs(&self) -> &dyn OrganisationsRepo {
        &self.work
    }
    fn users(&self) -> &dyn UsersRepo {
        &self.work
    }
    fn audit(&self) -> &dyn AuditLog {
        &self.work
    }
    fn connections(&self) -> &dyn ConnectionsRepo {
        &self.work
    }
    fn runs(&self) -> &dyn RunsRepo {
        &self.work
    }
    fn ledger(&self) -> &dyn Storage {
        &self.work
    }
    fn findings(&self) -> &dyn FindingsRepo {
        &self.work
    }
    fn resources(&self) -> &dyn ResourcesRepo {
        &self.work
    }
    fn recipients(&self) -> &dyn RecipientsRepo {
        &self.work
    }
    fn integrations(&self) -> &dyn IntegrationsRepo {
        &self.work
    }
    fn deliveries(&self) -> &dyn DeliveriesRepo {
        &self.work
    }
    fn schedules(&self) -> &dyn SchedulesRepo {
        &self.work
    }
}

#[async_trait]
impl Tx for MemTx {
    async fn commit(self: Box<Self>) -> RepoResult<()> {
        let done = self.work.state().clone();
        *self.parent.state() = done;
        Ok(())
    }
}

/// One page of `rows` (already tenant-filtered), newest first by `key`, as `db::page` does.
fn page<T>(mut rows: Vec<T>, key: fn(&T) -> Cursor, p: PageRequest) -> PageOf<T> {
    rows.sort_by_key(|r| std::cmp::Reverse(key(r)));
    let mut items: Vec<T> = rows
        .into_iter()
        .filter(|r| p.after.is_none_or(|a| key(r) < a))
        .collect();
    let more = items.len() as u64 > p.limit;
    items.truncate(p.limit as usize);
    let next = more.then(|| items.last().map(key)).flatten();
    PageOf { items, next }
}
