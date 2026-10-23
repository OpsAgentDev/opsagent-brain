//! The unit of work: every repository an action may touch, on one connection or one
//! transaction.
use async_trait::async_trait;
use opsagent_core::{audit::AuditLog, org::OrganisationsRepo, repo::RepoResult, user::UsersRepo};
use opsagent_deliver::repo::{DeliveriesRepo, IntegrationsRepo, RecipientsRepo, SchedulesRepo};

pub trait Repos: Send + Sync {
    fn orgs(&self) -> &dyn OrganisationsRepo;
    fn users(&self) -> &dyn UsersRepo;
    fn audit(&self) -> &dyn AuditLog;
    fn recipients(&self) -> &dyn RecipientsRepo;
    fn integrations(&self) -> &dyn IntegrationsRepo;
    fn deliveries(&self) -> &dyn DeliveriesRepo;
    fn schedules(&self) -> &dyn SchedulesRepo;
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
