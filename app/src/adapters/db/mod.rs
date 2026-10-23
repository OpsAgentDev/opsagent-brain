//! SeaORM implementations of the repository traits. `Pg` wraps a pool, a transaction, or a
//! borrowed handle to either.
mod audit;
mod connections;
mod deliveries;
mod findings;
mod integrations;
pub mod ledger_storage;
mod orgs;
mod page;
mod recipients;
mod resources;
mod runs;
mod schedules;
mod users;

use std::fmt::Display;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    audit::AuditLog,
    connection::ConnectionsRepo,
    finding::FindingsRepo,
    org::{OrganisationsRepo, Role},
    repo::{RepoError, RepoResult},
    resource::ResourcesRepo,
    run::RunsRepo,
    user::{Email, UsersRepo},
};
use opsagent_deliver::repo::{DeliveriesRepo, IntegrationsRepo, RecipientsRepo, SchedulesRepo};
use opsagent_ledger::Storage;
use sea_orm::{
    prelude::DateTimeWithTimeZone, ConnectionTrait, DatabaseConnection, DatabaseTransaction,
    TransactionTrait,
};

pub use connections::status_of;
pub use page::page;

use crate::actions::uow::{Repos, Tx, UnitOfWork};

/// A database handle `Pg` can run queries on.
pub trait Conn: Send + Sync {
    type C: ConnectionTrait;
    fn conn(&self) -> &Self::C;
}

impl Conn for DatabaseConnection {
    type C = Self;
    fn conn(&self) -> &Self {
        self
    }
}

impl Conn for DatabaseTransaction {
    type C = Self;
    fn conn(&self) -> &Self {
        self
    }
}

impl<T: ConnectionTrait> Conn for &T {
    type C = T;
    fn conn(&self) -> &T {
        self
    }
}

pub struct Pg<C = DatabaseConnection>(C);

impl<C: Conn> Pg<C> {
    pub fn new(c: C) -> Self {
        Self(c)
    }

    pub fn into_inner(self) -> C {
        self.0
    }

    /// The connection or transaction writes go to, for raw writes that must commit with them.
    pub fn db(&self) -> &C::C {
        self.0.conn()
    }
}

pub fn db_err(e: impl Display) -> RepoError {
    RepoError::Storage(e.to_string())
}

fn utc(t: DateTimeWithTimeZone) -> DateTime<Utc> {
    t.with_timezone(&Utc)
}

fn email(stored: &str) -> RepoResult<Email> {
    Email::parse(stored).ok_or_else(|| RepoError::Storage("stored email is not valid".into()))
}

fn role(stored: &str) -> RepoResult<Role> {
    Role::parse(stored).ok_or_else(|| RepoError::Storage(format!("unknown role {stored:?}")))
}

impl<C: Conn> Repos for Pg<C> {
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
impl UnitOfWork for Pg<DatabaseConnection> {
    async fn begin(&self) -> RepoResult<Box<dyn Tx>> {
        Ok(Box::new(Pg(self.0.begin().await.map_err(db_err)?)))
    }
}

#[async_trait]
impl Tx for Pg<DatabaseTransaction> {
    async fn commit(self: Box<Self>) -> RepoResult<()> {
        self.0.commit().await.map_err(db_err)
    }

    async fn savepoint(&self) -> RepoResult<Box<dyn Tx>> {
        Ok(Box::new(Pg(self.0.begin().await.map_err(db_err)?)))
    }
}
