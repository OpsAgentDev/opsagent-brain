//! The unit of work: every repository an action may touch, on one connection or one
//! transaction.
use async_trait::async_trait;
use opsagent_core::{
    audit::AuditLog, connection::ConnectionsRepo, finding::FindingsRepo, org::OrganisationsRepo,
    repo::RepoResult, resource::ResourcesRepo, run::RunsRepo, user::UsersRepo,
};
use opsagent_deliver::repo::{DeliveriesRepo, IntegrationsRepo, RecipientsRepo, SchedulesRepo};
use opsagent_ledger::Storage;
use uuid::Uuid;

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
    fn recipients(&self) -> &dyn RecipientsRepo;
    fn integrations(&self) -> &dyn IntegrationsRepo;
    fn deliveries(&self) -> &dyn DeliveriesRepo;
    fn schedules(&self) -> &dyn SchedulesRepo;
}

/// Writes through a `Tx` are discarded unless it is committed.
#[async_trait]
pub trait Tx: Repos {
    async fn commit(self: Box<Self>) -> RepoResult<()>;
    /// A nested transaction: dropping it undoes only its own writes, and a failed statement
    /// inside it leaves this one usable. Do not use this one while it is open.
    async fn savepoint(&self) -> RepoResult<Box<dyn Tx>>;
    /// Holds run `run_id` until this transaction ends if `fence` is still its fence, so a
    /// superseded worker cannot commit; `Err(StaleFence)` otherwise.
    async fn hold_fence(&self, run_id: Uuid, fence: u64) -> opsagent_ledger::Result<()>;
}

#[async_trait]
pub trait UnitOfWork: Repos {
    async fn begin(&self) -> RepoResult<Box<dyn Tx>>;
}
