//! Inventory use cases.
mod get_costs;
mod list_resources;

pub use get_costs::{Costs, FlaggedDay, GetCosts};
pub use list_resources::ListResources;

pub struct Resources {
    pub list_resources: ListResources,
    pub get_costs: GetCosts,
}
