//! The unit of work: every repository an action may touch, on one connection or one
//! transaction.
use async_trait::async_trait;
use opsagent_core::{
    audit::AuditLog, connection::ConnectionsRepo, finding::FindingsRepo, org::OrganisationsRepo,
    repo::RepoResult, resource::ResourcesRepo, run::RunsRepo, user::UsersRepo,
};
use opsagent_ledger::Storage;

pub trait Repos: Send + Sync {
    fn orgs(&self) -> &dyn OrganisationsRepo;
    fn users(&self) -> &dyn UsersRepo;
    fn audit(&self) -> &dyn AuditLog;
    fn connections(&self) -> &dyn ConnectionsRepo;
    /// Runs, read side.
    fn runs(&self) -> &dyn RunsRepo;
    /// Runs, write side: creation, fences, checkpoints, effects.
    fn ledger(&self) -> &dyn Storage;
    fn findings(&self) -> &dyn FindingsRepo;
    fn resources(&self) -> &dyn ResourcesRepo;
}

/// Writes through a `Tx` are discarded unless it is committed.
#[async_trait]
pub trait Tx: Repos {
    async fn commit(self: Box<Self>) -> RepoResult<()>;
}

#[async_trait]
pub trait UnitOfWork: Repos {
    async fn begin(&self) -> RepoResult<Box<dyn Tx>>;
}
