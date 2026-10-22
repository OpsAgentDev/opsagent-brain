pub mod csrf;
pub mod org_scope;
pub mod session;

use async_trait::async_trait;
use axum::{middleware::from_fn_with_state, Router as AxumRouter};
use loco_rs::{
    app::{AppContext, Initializer},
    environment::Environment,
    Result,
};
use std::sync::Arc;

use crate::{mailers, settings::Settings};

/// Installs settings, the mailer, the session layer and the CSRF guard.
pub struct AuthInitializer;

#[async_trait]
impl Initializer for AuthInitializer {
    fn name(&self) -> String {
        "auth".into()
    }

    async fn after_routes(&self, router: AxumRouter, ctx: &AppContext) -> Result<AxumRouter> {
        let settings = Settings::load(ctx)?;
        let layer = session::layer(ctx.db.clone(), &settings);
        ctx.shared_store.insert(settings);
        let production = ctx.environment == Environment::Production;
        ctx.shared_store.insert(mailers::from_env(production)?);
        // Last layer is outermost: the session must load before the CSRF guard runs.
        Ok(router
            .layer(from_fn_with_state(ctx.clone(), csrf::guard))
            .layer(layer))
    }
}

/// The mailer installed by `AuthInitializer` (tests may replace it in the shared store).
pub fn mailer(ctx: &AppContext) -> Arc<dyn mailers::Mailer> {
    ctx.shared_store
        .get::<Arc<dyn mailers::Mailer>>()
        .expect("mailer not installed")
}
