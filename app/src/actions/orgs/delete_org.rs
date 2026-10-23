use std::sync::Arc;

use opsagent_core::{audit::AuditEntry, repo::Clock};
use uuid::Uuid;

use super::OrgScope;
use crate::{
    actions::{connections::end_connection, uow::UnitOfWork},
    error::AppResult,
};

/// Soft-deletes the organisation, in one transaction: every connection is disconnected and
/// every schedule disabled, so nothing is scanned for it again. Owners only.
pub struct DeleteOrg {
    uow: Arc<dyn UnitOfWork>,
    clock: Arc<dyn Clock>,
}

impl DeleteOrg {
    pub fn new(uow: Arc<dyn UnitOfWork>, clock: Arc<dyn Clock>) -> Self {
        Self { uow, clock }
    }

    pub async fn run(&self, scope: &OrgScope, actor: Uuid) -> AppResult<()> {
        scope.require_owner()?;
        // TODO(billing): cancel the Stripe subscription before marking the org deleted.
        let organisation_id = scope.organisation.id;
        let tx = self.uow.begin().await?;
        tx.orgs().lock(organisation_id).await?;
        tx.orgs()
            .soft_delete(organisation_id, self.clock.now())
            .await?;
        for c in tx.connections().list(organisation_id).await? {
            end_connection(tx.as_ref(), organisation_id, c.id, "organisation_deleted").await?;
        }
        tx.schedules().disable_for_org(organisation_id).await?;
        let target = Some(("organisation", organisation_id.to_string()));
        let entry = AuditEntry::member(Some(organisation_id), actor, "org.delete", target);
        tx.audit().record(entry).await?;
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::error::AppError;
    use async_trait::async_trait;
    use chrono::{DateTime, NaiveTime, Utc};
    use opsagent_core::{
        audit::AuditLog,
        connection::{ConnectionStatus, ConnectionsRepo, NewConnection, SealedCreds},
        finding::FindingsRepo,
        org::OrganisationsRepo,
        repo::{RepoError, RepoResult, SystemClock},
        resource::ResourcesRepo,
        run::{RunKey, RunsRepo},
        user::UsersRepo,
    };
    use opsagent_deliver::repo::{
        DeliveriesRepo, DueRun, IntegrationsRepo, RecipientsRepo, SchedulesRepo, SinceFn,
    };
    use opsagent_ledger::Storage;

    use super::*;
    use crate::{
        actions::{
            orgs::test_support::*,
            uow::{Repos, Tx},
        },
        adapters::memory::MemStore,
    };

    /// Every schedule write fails.
    struct BrokenSchedules;

    #[async_trait]
    impl SchedulesRepo for BrokenSchedules {
        async fn create_defaults(
            &self,
            _: Uuid,
            _: Uuid,
            _: (Option<NaiveTime>, Option<NaiveTime>),
            _: DateTime<Utc>,
        ) -> RepoResult<()> {
            Err(broken())
        }
        async fn set_cron(
            &self,
            _: Uuid,
            _: Uuid,
            _: &str,
            _: &str,
            _: SinceFn<'_>,
        ) -> RepoResult<()> {
            Err(broken())
        }
        async fn disable_for_org(&self, _: Uuid) -> RepoResult<u64> {
            Err(broken())
        }
        async fn backfill_defaults(&self, _: DateTime<Utc>) -> RepoResult<u64> {
            Err(broken())
        }
        async fn due_ids(&self, _: DateTime<Utc>) -> RepoResult<Vec<Uuid>> {
            Err(broken())
        }
        async fn lock_due(
            &self,
            _: Uuid,
            _: DateTime<Utc>,
        ) -> RepoResult<Option<(RunKey, String, String)>> {
            Err(broken())
        }
        async fn advance(&self, _: Uuid, _: Option<DateTime<Utc>>) -> RepoResult<()> {
            Err(broken())
        }
        async fn due_runs(&self, _: DateTime<Utc>) -> RepoResult<Vec<DueRun>> {
            Err(broken())
        }
        async fn try_lock_scheduler(&self) -> RepoResult<bool> {
            Err(broken())
        }
    }

    fn broken() -> RepoError {
        RepoError::Storage("schedules down".into())
    }

    /// `R` with its schedules replaced by `BrokenSchedules`.
    struct WithBrokenSchedules<R>(R);

    /// `Repos` for `WithBrokenSchedules<$t>`, delegating all but `schedules`.
    macro_rules! with_broken_schedules {
        ($t:ty) => {
            impl Repos for WithBrokenSchedules<$t> {
                fn orgs(&self) -> &dyn OrganisationsRepo {
                    self.0.orgs()
                }
                fn users(&self) -> &dyn UsersRepo {
                    self.0.users()
                }
                fn audit(&self) -> &dyn AuditLog {
                    self.0.audit()
                }
                fn connections(&self) -> &dyn ConnectionsRepo {
                    self.0.connections()
                }
                fn runs(&self) -> &dyn RunsRepo {
                    self.0.runs()
                }
                fn ledger(&self) -> &dyn Storage {
                    self.0.ledger()
                }
                fn findings(&self) -> &dyn FindingsRepo {
                    self.0.findings()
                }
                fn resources(&self) -> &dyn ResourcesRepo {
                    self.0.resources()
                }
                fn recipients(&self) -> &dyn RecipientsRepo {
                    self.0.recipients()
                }
                fn integrations(&self) -> &dyn IntegrationsRepo {
                    self.0.integrations()
                }
                fn deliveries(&self) -> &dyn DeliveriesRepo {
                    self.0.deliveries()
                }
                fn schedules(&self) -> &dyn SchedulesRepo {
                    &BrokenSchedules
                }
            }
        };
    }
    with_broken_schedules!(Arc<MemStore>);
    with_broken_schedules!(Box<dyn Tx>);

    #[async_trait]
    impl UnitOfWork for WithBrokenSchedules<Arc<MemStore>> {
        async fn begin(&self) -> RepoResult<Box<dyn Tx>> {
            Ok(Box::new(WithBrokenSchedules(self.0.begin().await?)))
        }
    }

    #[async_trait]
    impl Tx for WithBrokenSchedules<Box<dyn Tx>> {
        async fn commit(self: Box<Self>) -> RepoResult<()> {
            self.0.commit().await
        }
        async fn savepoint(&self) -> RepoResult<Box<dyn Tx>> {
            Ok(Box::new(WithBrokenSchedules(self.0.savepoint().await?)))
        }
    }

    async fn connection(store: &MemStore, organisation_id: Uuid) -> Uuid {
        let new = NewConnection {
            organisation_id,
            provider: "aws".into(),
            display_name: "prod".into(),
            template_version: None,
            credential_kind: "role_arn".into(),
        };
        let creds = SealedCreds {
            ciphertext: vec![],
            nonce: vec![],
            kek_version: 1,
        };
        ConnectionsRepo::insert(store, new, creds).await.unwrap().id
    }

    async fn status(store: &MemStore, org: Uuid, id: Uuid) -> ConnectionStatus {
        store
            .connections()
            .get(org, id)
            .await
            .unwrap()
            .unwrap()
            .status
    }

    #[tokio::test]
    async fn delete_org_disables_schedules_and_ends_connections_in_one_tx() {
        let store = MemStore::default();
        let (owner, org) = owned_org(&store, "o@example.com", "Doomed").await;
        let conn = connection(&store, org.id).await;
        let now = Utc::now();
        store
            .create_defaults(org.id, conn, (None, None), now)
            .await
            .unwrap();
        let schedules = store.enabled_schedules(org.id);
        assert!(schedules > 0);
        let scope = scope(&store, &org, &owner).await;

        // A failing schedule write after the soft delete and the disconnect rolls back both.
        let broken = WithBrokenSchedules(Arc::new(store.clone()));
        let refused = DeleteOrg::new(Arc::new(broken), Arc::new(SystemClock));
        let err = refused.run(&scope, owner.id).await.unwrap_err();
        assert!(
            matches!(err, AppError::Repo(RepoError::Storage(_))),
            "{err:?}"
        );
        assert!(!store.is_deleted(org.id).await.unwrap());
        assert_eq!(
            status(&store, org.id, conn).await,
            ConnectionStatus::Pending
        );
        assert!(store
            .audit_entries()
            .iter()
            .all(|e| e.action != "org.delete"));
        assert_eq!(store.enabled_schedules(org.id), schedules);

        let delete = DeleteOrg::new(Arc::new(store.clone()), Arc::new(SystemClock));
        delete.run(&scope, owner.id).await.unwrap();
        assert!(store.is_deleted(org.id).await.unwrap());
        assert_eq!(
            status(&store, org.id, conn).await,
            ConnectionStatus::Disconnected
        );
        assert_eq!(store.enabled_schedules(org.id), 0);
        let deleted = store.audit_entries();
        assert_eq!(
            deleted.iter().filter(|e| e.action == "org.delete").count(),
            1
        );
    }
}
