use std::sync::Arc;

use opsagent_core::{
    audit::AuditEntry,
    billing::{BillingError, BillingProvider, BillingStatus},
    repo::Clock,
};
use uuid::Uuid;

use super::OrgScope;
use crate::{
    actions::{
        billing::{provider_failed, unavailable},
        connections::end_connection,
        uow::UnitOfWork,
    },
    error::AppResult,
};

/// Soft-deletes the organisation, in one transaction: every connection is disconnected and
/// every schedule disabled, so nothing is scanned for it again. Owners only. A live Stripe
/// subscription is cancelled first; if Stripe fails, nothing is deleted (502, or 503 unconfigured).
pub struct DeleteOrg {
    uow: Arc<dyn UnitOfWork>,
    clock: Arc<dyn Clock>,
    billing: Arc<dyn BillingProvider>,
    stripe_configured: bool,
}

impl DeleteOrg {
    pub fn new(
        uow: Arc<dyn UnitOfWork>,
        clock: Arc<dyn Clock>,
        billing: Arc<dyn BillingProvider>,
        stripe_configured: bool,
    ) -> Self {
        Self {
            uow,
            clock,
            billing,
            stripe_configured,
        }
    }

    pub async fn run(&self, scope: &OrgScope, actor: Uuid) -> AppResult<()> {
        scope.require_owner()?;
        let organisation_id = scope.organisation.id;
        self.cancel_subscription(organisation_id).await?;
        let tx = self.uow.begin().await?;
        tx.orgs().lock(organisation_id).await?;
        tx.orgs()
            .soft_delete(organisation_id, self.clock.now())
            .await?;
        for c in tx.connections().list(organisation_id).await? {
            end_connection(tx.as_ref(), organisation_id, c.id, "organisation_deleted").await?;
        }
        tx.schedules().disable_for_org(organisation_id).await?;
        tx.oauth()
            .revoke_org_grants(organisation_id, self.clock.now())
            .await?;
        let target = Some(("organisation", organisation_id.to_string()));
        let entry = AuditEntry::member(Some(organisation_id), actor, "org.delete", target);
        tx.audit().record(entry).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Cancels the subscription unless there is none (or it already ended); Stripe having no
    /// such subscription (404) counts as cancelled. A live one with Stripe unconfigured is
    /// refused (503): deleting would leave it billing.
    async fn cancel_subscription(&self, organisation_id: Uuid) -> AppResult<()> {
        let b = self.uow.billing().billing(organisation_id).await?;
        let ended = matches!(
            b.status,
            BillingStatus::Canceled | BillingStatus::TrialEnded
        );
        let Some(sub) = b.subscription.filter(|_| !ended) else {
            return Ok(());
        };
        if !self.stripe_configured {
            return Err(unavailable());
        }
        let id = sub.subscription_id;
        let idem = format!("org_delete:{organisation_id}:{id}");
        match self.billing.cancel_subscription(&id, &idem).await {
            Ok(()) | Err(BillingError::NotFound) => Ok(()),
            Err(e) => Err(provider_failed(e)),
        }
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

    /// Stripe unconfigured: never called.
    fn no_stripe() -> Arc<dyn opsagent_core::billing::BillingProvider> {
        use crate::adapters::stripe::{StripeBilling, StripeSettings};
        let s = StripeSettings {
            api_base: "http://127.0.0.1:9".into(),
            secret_key: String::new(),
            api_version: String::new(),
            automatic_tax: false,
        };
        Arc::new(StripeBilling::new(s).unwrap())
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
                fn oauth(&self) -> &dyn opsagent_core::oauth::OAuthRepo {
                    self.0.oauth()
                }
                fn passkeys(&self) -> &dyn opsagent_core::passkey::PasskeysRepo {
                    self.0.passkeys()
                }
                fn retention(&self) -> &dyn opsagent_core::retention::RetentionRepo {
                    self.0.retention()
                }
                fn billing(&self) -> &dyn opsagent_core::billing::BillingRepo {
                    self.0.billing()
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
        fn queue(&self) -> &dyn opsagent_ledger::Queue {
            self.0.queue()
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
        let refused = DeleteOrg::new(Arc::new(broken), Arc::new(SystemClock), no_stripe(), false);
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

        let delete = DeleteOrg::new(
            Arc::new(store.clone()),
            Arc::new(SystemClock),
            no_stripe(),
            false,
        );
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

    #[tokio::test]
    async fn delete_org_refuses_503_with_live_subscription_and_no_stripe() {
        use opsagent_core::billing::{BillingRepo, BillingStatus as B, SubscriptionState};
        let store = MemStore::default();
        let (owner, org) = owned_org(&store, "o@example.com", "Billed").await;
        let mut s = SubscriptionState {
            subscription_id: "sub_1".into(),
            status: B::Active,
            tier: None,
            quantity: 1,
            trial_ends_at: None,
            current_period_start: None,
            current_period_end: None,
        };
        let at = Utc::now();
        store.apply_subscription(org.id, &s, at).await.unwrap();
        let scope = scope(&store, &org, &owner).await;
        let store_uow = Arc::new(store.clone());
        let delete = DeleteOrg::new(store_uow, Arc::new(SystemClock), no_stripe(), false);
        let err = delete.run(&scope, owner.id).await.unwrap_err();
        assert!(
            matches!(&err, AppError::Refused { status, code, .. }
                if status.as_u16() == 503 && *code == "billing_unavailable"),
            "{err:?}"
        );
        assert!(!store.is_deleted(org.id).await.unwrap());
        // Ended: nothing to cancel, so the delete goes ahead.
        s.status = B::Canceled;
        let later = at + chrono::Duration::seconds(1);
        store.apply_subscription(org.id, &s, later).await.unwrap();
        delete.run(&scope, owner.id).await.unwrap();
        assert!(store.is_deleted(org.id).await.unwrap());
    }
}
