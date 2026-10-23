//! In-memory fakes of every repository, for tests. `begin` snapshots the whole state and
//! `commit` writes the snapshot back, so a dropped transaction leaves nothing behind.
mod audit;
mod connections;
mod orgs;
mod runs;
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
    org::{Invite, Organisation, OrganisationsRepo, Role},
    repo::RepoResult,
    run::RunsRepo,
    user::{User, UsersRepo},
};
use opsagent_ledger::Storage;
use uuid::Uuid;

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
}

#[async_trait]
impl Tx for MemTx {
    async fn commit(self: Box<Self>) -> RepoResult<()> {
        let done = self.work.state().clone();
        *self.parent.state() = done;
        Ok(())
    }
}
