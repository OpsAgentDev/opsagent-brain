//! OAuth use cases (nothing here names MCP; the resource URL comes from config).
mod register_client;
mod resolve_client;

pub use register_client::{RegisterClient, RegistrationRequest};
pub use resolve_client::ResolveClient;

pub struct OAuth {
    pub register_client: RegisterClient,
    pub resolve_client: ResolveClient,
}
