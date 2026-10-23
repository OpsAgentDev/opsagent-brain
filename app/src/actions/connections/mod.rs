//! Connection use cases (PRD 7.2): create, read, update, verify, disconnect.
mod create_connection;
mod disconnect_connection;
mod get_connection;
mod list_connections;
mod request_verify;
mod update_connection;

use axum::http::StatusCode;

pub use create_connection::{CreateConnection, Created};
pub use disconnect_connection::{end, DisconnectConnection};
pub use get_connection::GetConnection;
pub use list_connections::ListConnections;
pub use request_verify::RequestVerify;
pub use update_connection::{PatchInput, UpdateConnection};

use crate::error::AppError;

pub const TEMPLATE_VERSION: &str = "1";

pub struct Connections {
    pub create_connection: CreateConnection,
    pub list_connections: ListConnections,
    pub get_connection: GetConnection,
    pub update_connection: UpdateConnection,
    pub request_verify: RequestVerify,
    pub disconnect_connection: DisconnectConnection,
}

fn disconnected() -> AppError {
    AppError::Refused {
        status: StatusCode::CONFLICT,
        code: "connection_disconnected",
        detail: "This connection was disconnected. Start a new connection instead.".into(),
    }
}
