//! Repository contracts: every test body runs against `Pg` (the lane database, schema recreated
//! and migrated per boot) and against the in-memory `MemStore`; both must pass.
use loco_rs::testing::prelude::boot_test;
use opsagent_brain::{adapters::db::Pg, app::App};

mod connections;
mod orgs;
mod runs;
mod users;

/// A fresh, migrated lane database (`boot_test` recreates the schema).
pub async fn pg() -> Pg {
    crate::requests::support::test_env();
    let boot = boot_test::<App>().await.expect("boot");
    Pg::new(boot.app_context.db.clone())
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
