//! OAuth and discovery endpoints: the public router (no session, cookie or CSRF).
mod discovery;
pub mod error;
mod register;

use axum::Router;

use crate::state::AppState;

pub use error::OAuthError;

pub fn routes() -> Router<AppState> {
    discovery::routes().merge(register::routes())
}
