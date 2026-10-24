//! OAuth and discovery endpoints: the public router (no session, cookie or CSRF).
mod authorize;
mod discovery;
pub mod error;
mod register;
mod token;

use axum::Router;

use crate::state::AppState;

pub use error::OAuthError;

pub fn routes() -> Router<AppState> {
    discovery::routes()
        .merge(register::routes())
        .merge(authorize::routes())
        .merge(token::routes())
}
