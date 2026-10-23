pub mod connections;
pub mod deliveries;
pub mod finding_lifecycle;
pub mod integrations;
pub mod inventory_upsert;
pub mod mail_guard;
pub mod manual_scan;
pub mod members;
pub mod orgs;
/// shortcut: `controllers/runs.rs` (Task 7's lane) still imports this path; delete when it moves
/// to `controllers::page`.
pub mod pagination {
    pub use crate::controllers::page::{page_request as request, Page, PageParams};
}
pub mod posture;
pub mod recipients;
pub mod runs;
