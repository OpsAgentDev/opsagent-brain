//! Repository contracts: every test body runs against `Pg` (the lane database, schema recreated
//! and migrated per boot) and against the in-memory `MemStore`; both must pass.
use loco_rs::testing::prelude::boot_test;
use opsagent_brain::{actions::uow::Repos, adapters::db::Pg, app::App};
use opsagent_core::org::NewOrganisation;
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};
use uuid::Uuid;

mod deliveries;
mod integrations;
mod orgs;
mod recipients;
mod schedules;
mod users;

/// A fresh, migrated lane database (`boot_test` recreates the schema).
pub async fn pg() -> Pg {
    pg_db().await.0
}

/// `pg()` and its connection pool, for seeding rows no repository here owns.
pub async fn pg_db() -> (Pg, DatabaseConnection) {
    crate::requests::support::test_env();
    let boot = boot_test::<App>().await.expect("boot");
    let db = boot.app_context.db.clone();
    (Pg::new(db.clone()), db)
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

/// A pending connection row in `org`.
pub async fn pg_connection(db: &DatabaseConnection, org: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let sql = "INSERT INTO connections (id, organisation_id, provider) VALUES ($1, $2, 'aws')";
    let st = Statement::from_sql_and_values(DbBackend::Postgres, sql, [id.into(), org.into()]);
    db.execute_raw(st).await.unwrap();
    id
}

/// `contract_suite! { async fn name(s) { body } ... }`: `s` is a `&dyn UnitOfWork`; each
/// `name` becomes a module with a `pg` and a `mem` test.
macro_rules! contract_suite {
    ($(async fn $name:ident($s:ident) $body:block)*) => {$(
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            #[tokio::test]
            #[serial_test::serial]
            async fn pg() {
                let store = crate::contracts::pg().await;
                let $s: &dyn opsagent_brain::actions::uow::UnitOfWork = &store;
                $body
            }

            #[tokio::test]
            async fn mem() {
                let store = opsagent_brain::adapters::memory::MemStore::default();
                let $s: &dyn opsagent_brain::actions::uow::UnitOfWork = &store;
                $body
            }
        }
    )*};
}
pub(crate) use contract_suite;

/// As `contract_suite!`, for rows that reference a connection: `$o` is a fresh organisation
/// and `$c` a connection in it (a real row on Pg; MemStore keeps no connections).
macro_rules! conn_suite {
    ($(async fn $name:ident($s:ident, $o:ident, $c:ident) $body:block)*) => {$(
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            #[tokio::test]
            #[serial_test::serial]
            async fn pg() {
                let (store, db) = crate::contracts::pg_db().await;
                let $s: &dyn opsagent_brain::actions::uow::UnitOfWork = &store;
                let $o = crate::contracts::org_id($s, "acme").await;
                let $c = crate::contracts::pg_connection(&db, $o).await;
                $body
            }

            #[tokio::test]
            async fn mem() {
                let store = opsagent_brain::adapters::memory::MemStore::default();
                let $s: &dyn opsagent_brain::actions::uow::UnitOfWork = &store;
                let $o = crate::contracts::org_id($s, "acme").await;
                let $c = uuid::Uuid::new_v4();
                $body
            }
        }
    )*};
}
pub(crate) use conn_suite;
