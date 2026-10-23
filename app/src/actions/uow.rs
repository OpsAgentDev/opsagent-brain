//! The unit of work: every repository an action may touch, on one connection or one
//! transaction.
use async_trait::async_trait;
use opsagent_core::{
    audit::AuditLog, finding::FindingsRepo, org::OrganisationsRepo, repo::RepoResult,
    resource::ResourcesRepo, user::UsersRepo,
};

pub trait Repos: Send + Sync {
    fn orgs(&self) -> &dyn OrganisationsRepo;
    fn users(&self) -> &dyn UsersRepo;
    fn audit(&self) -> &dyn AuditLog;
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
