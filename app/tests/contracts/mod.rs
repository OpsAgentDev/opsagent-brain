//! Repository contracts: every test body runs against `Pg` (the lane database, schema recreated
//! and migrated per boot) and against the in-memory `MemStore`; both must pass.
use async_trait::async_trait;
use opsagent_brain::{
    actions::uow::Repos,
    adapters::{db::Pg, memory::MemStore},
};
use opsagent_core::org::NewOrganisation;
use sea_orm::{ConnectionTrait, Database, DatabaseConnection};
use uuid::Uuid;

mod connections;
mod deliveries;
mod findings;
mod integrations;
mod orgs;
mod recipients;
mod resources;
mod runs;
mod schedules;
mod users;

/// A fresh, migrated lane database (`TestApp` recreates the schema).
pub async fn pg() -> Pg {
    Pg::new(crate::support::TestApp::boot().await.db)
}

/// A new organisation in zone `UTC`.
pub async fn org_id(s: &dyn Repos, slug: &str) -> Uuid {
    let new = NewOrganisation {
        id: Uuid::new_v4(),
        slug: slug.into(),
        name: format!("Org {slug}"),
        timezone: "UTC".into(),
        kek_version: 1,
        wrapped_dek: vec![1, 2, 3],
    };
    s.orgs().insert(new).await.unwrap().id
}

/// Parent rows a repository under test needs but does not own (foreign keys on Pg).
#[async_trait]
pub trait Seed: Sync {
    async fn connection(&self, organisation_id: Uuid) -> Uuid;
    async fn run(&self, organisation_id: Uuid, connection_id: Uuid) -> Uuid;
    /// Marks the resource gone, as the full-scan worker does after a complete inventory.
    async fn resource_gone(&self, organisation_id: Uuid, identity: &str);
}

/// Seeds the lane database over its own connection (the app pool has one connection).
pub struct PgSeed(DatabaseConnection);

impl PgSeed {
    pub async fn new() -> Self {
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
        Self(Database::connect(url).await.expect("seed connection"))
    }

    fn raw(&self) -> &DatabaseConnection {
        &self.0
    }
}

#[async_trait]
impl Seed for PgSeed {
    async fn connection(&self, organisation_id: Uuid) -> Uuid {
        let id = Uuid::now_v7();
        self.raw()
            .execute_unprepared(&format!(
                "INSERT INTO connections (id, organisation_id, provider) VALUES ('{id}', '{organisation_id}', 'fake')"
            ))
            .await
            .unwrap();
        id
    }

    async fn run(&self, organisation_id: Uuid, connection_id: Uuid) -> Uuid {
        let id = Uuid::now_v7();
        self.raw()
            .execute_unprepared(&format!(
                "INSERT INTO runs (id, organisation_id, connection_id, job_type, scheduled_at) \
                 VALUES ('{id}', '{organisation_id}', '{connection_id}', 'full_scan', now())"
            ))
            .await
            .unwrap();
        id
    }

    async fn resource_gone(&self, organisation_id: Uuid, identity: &str) {
        self.raw()
            .execute_unprepared(&format!(
                "UPDATE resources SET gone_at = now() WHERE organisation_id = '{organisation_id}' \
                 AND identity = '{identity}'"
            ))
            .await
            .unwrap();
    }
}

#[async_trait]
impl Seed for MemStore {
    async fn connection(&self, _: Uuid) -> Uuid {
        Uuid::now_v7()
    }

    async fn run(&self, _: Uuid, _: Uuid) -> Uuid {
        Uuid::now_v7()
    }

    async fn resource_gone(&self, organisation_id: Uuid, identity: &str) {
        self.mark_resource_gone(organisation_id, identity, chrono::Utc::now());
    }
}

/// `contract_suite! { async fn name(s) { body } ... }`: `s` is a `&dyn UnitOfWork`; each
/// `name` becomes a module with a `pg` and a `mem` test. `async fn name(s, seed)` also binds
/// `seed: &dyn Seed` for parent rows.
macro_rules! contract_suite {
    ($(async fn $name:ident($s:ident $(, $seed:ident)?) $body:block)*) => {$(
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            #[tokio::test]
            #[serial_test::serial]
            async fn pg() {
                let store = crate::contracts::pg().await;
                let $s: &dyn opsagent_brain::actions::uow::UnitOfWork = &store;
                $(let seed = crate::contracts::PgSeed::new().await;
                let $seed: &dyn crate::contracts::Seed = &seed;)?
                $body
            }

            #[tokio::test]
            async fn mem() {
                let store = opsagent_brain::adapters::memory::MemStore::default();
                let $s: &dyn opsagent_brain::actions::uow::UnitOfWork = &store;
                $(let $seed: &dyn crate::contracts::Seed = &store;)?
                $body
            }
        }
    )*};
}
pub(crate) use contract_suite;
mod queue;
