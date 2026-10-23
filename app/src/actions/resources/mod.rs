//! Inventory use cases.
mod list_resources;

pub use list_resources::ListResources;

pub struct Resources {
    pub list_resources: ListResources,
}
