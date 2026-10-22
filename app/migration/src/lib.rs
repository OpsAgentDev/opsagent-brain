#![allow(elided_lifetimes_in_paths)]
#![allow(clippy::wildcard_imports)]
pub use sea_orm_migration::prelude::*;

mod m20261022_000001_tenancy;
mod m20261022_000002_connections;
mod m20261022_000003_ledger;
mod m20261022_000004_inventory;
mod m20261022_000005_audit;
mod m20261022_000006_finding_stability;
mod m20261022_000007_customer_finding_events;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20261022_000001_tenancy::Migration),
            Box::new(m20261022_000002_connections::Migration),
            Box::new(m20261022_000003_ledger::Migration),
            Box::new(m20261022_000004_inventory::Migration),
            Box::new(m20261022_000005_audit::Migration),
            Box::new(m20261022_000006_finding_stability::Migration),
            Box::new(m20261022_000007_customer_finding_events::Migration),
            // inject-above (do not remove this comment)
        ]
    }
}
