//! The unit of work: every repository an action may touch, on one connection or one
//! transaction.
use async_trait::async_trait;
use opsagent_core::{
    audit::AuditLog, connection::ConnectionsRepo, finding::FindingsRepo, oauth::OAuthRepo,
    org::OrganisationsRepo, passkey::PasskeysRepo, repo::RepoResult, resource::ResourcesRepo,
    retention::RetentionRepo, run::RunsRepo, user::UsersRepo,
};
use opsagent_deliver::repo::{DeliveriesRepo, IntegrationsRepo, RecipientsRepo, SchedulesRepo};
use opsagent_ledger::{Queue, Storage};

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
    fn oauth(&self) -> &dyn OAuthRepo;
    fn passkeys(&self) -> &dyn PasskeysRepo;
    /// The nightly retention job's global deletes.
    fn retention(&self) -> &dyn RetentionRepo;
}

/// Writes through a `Tx` are discarded unless it is committed.
#[async_trait]
pub trait Tx: Repos {
    async fn commit(self: Box<Self>) -> RepoResult<()>;
    /// Jobs enqueued here are dequeued only once this transaction commits.
    fn queue(&self) -> &dyn Queue;
    /// A nested transaction: dropping it undoes only its own writes, and a failed statement
    /// inside it leaves this one usable. Do not use this one while it is open.
    async fn savepoint(&self) -> RepoResult<Box<dyn Tx>>;
}

#[async_trait]
pub trait UnitOfWork: Repos {
    async fn begin(&self) -> RepoResult<Box<dyn Tx>>;
}
