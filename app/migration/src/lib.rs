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
mod m20261022_000008_deliveries;
mod m20261022_000009_email_suppressions;
mod m20261022_000010_delivery_status;
mod m20261023_000011_jobs;
mod m20261024_000012_oauth;
mod m20261024_000013_magic_link_return_to;
mod m20261027_000014_waitlist;
mod m20261028_000015_contact;
mod m20261028_000016_sign_in;
mod m20261028_000017_urgent_alerts;
mod m20261028_000018_resource_history_run_idx;
mod m20261028_000019_retention;
mod m20261028_000020_audit_purge;
mod m20261029_000021_billing;
mod m20261030_000022_dashboard_ai;

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
            Box::new(m20261022_000008_deliveries::Migration),
            Box::new(m20261022_000009_email_suppressions::Migration),
            Box::new(m20261022_000010_delivery_status::Migration),
            Box::new(m20261023_000011_jobs::Migration),
            Box::new(m20261024_000012_oauth::Migration),
            Box::new(m20261024_000013_magic_link_return_to::Migration),
            Box::new(m20261027_000014_waitlist::Migration),
            Box::new(m20261028_000015_contact::Migration),
            Box::new(m20261028_000016_sign_in::Migration),
            Box::new(m20261028_000017_urgent_alerts::Migration),
            Box::new(m20261028_000018_resource_history_run_idx::Migration),
            Box::new(m20261028_000019_retention::Migration),
            Box::new(m20261028_000020_audit_purge::Migration),
            Box::new(m20261029_000021_billing::Migration),
            Box::new(m20261030_000022_dashboard_ai::Migration),
            // inject-above (do not remove this comment)
        ]
    }
}
