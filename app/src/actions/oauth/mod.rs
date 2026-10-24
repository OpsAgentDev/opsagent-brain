//! OAuth use cases (nothing here names MCP; the resource URL comes from config).
mod register_client;

pub use register_client::{RegisterClient, RegistrationRequest};

pub struct OAuth {
    pub register_client: RegisterClient,
}
