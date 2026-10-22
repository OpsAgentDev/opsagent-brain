pub mod csrf;
pub mod org_scope;
pub mod request_span;
pub mod session;

use async_trait::async_trait;
use axum::{
    http::{header, HeaderName, HeaderValue, Method},
    middleware::from_fn_with_state,
    Router as AxumRouter,
};
use loco_rs::{
    app::{AppContext, Initializer},
    environment::Environment,
    Result,
};
use std::sync::Arc;
use tower_http::cors::CorsLayer;

use crate::{
    adapters::slack::{HttpSlack, SlackClient},
    mailers,
    settings::Settings,
};

/// Installs settings, the mailer, the Slack client, the session layer and the CSRF guard.
pub struct AuthInitializer;

#[async_trait]
impl Initializer for AuthInitializer {
    fn name(&self) -> String {
        "auth".into()
    }

    async fn after_routes(&self, router: AxumRouter, ctx: &AppContext) -> Result<AxumRouter> {
        let settings = Settings::load(ctx)?;
        let layer = session::layer(ctx.db.clone(), &settings);
        let cors = cors_layer(&settings.web_base_url)?;
        let slack: Arc<dyn SlackClient> = Arc::new(HttpSlack::new(&settings.slack_api_base_url));
        ctx.shared_store.insert(slack);
        ctx.shared_store.insert(settings);
        let production = ctx.environment == Environment::Production;
        ctx.shared_store.insert(mailers::from_env(production)?);
        // Last layer is outermost: the session must load before the CSRF guard runs, and CORS
        // wraps both so their error responses still reach the browser.
        Ok(router
            .layer(from_fn_with_state(ctx.clone(), csrf::guard))
            .layer(layer)
            .layer(cors))
    }
}

/// The web origin only, with credentials (the session cookie); headers and methods must be
/// listed explicitly because credentials forbid wildcards.
fn cors_layer(web_base_url: &str) -> Result<CorsLayer> {
    let origin: HeaderValue = web_base_url
        .trim_end_matches('/')
        .parse()
        .map_err(|_| loco_rs::Error::string("WEB_BASE_URL is not a valid origin"))?;
    Ok(CorsLayer::new()
        .allow_origin(origin)
        .allow_credentials(true)
        .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE])
        .allow_headers([
            header::CONTENT_TYPE,
            HeaderName::from_static("x-csrf-token"),
        ]))
}

/// The mailer installed by `AuthInitializer` (tests may replace it in the shared store).
pub fn mailer(ctx: &AppContext) -> Arc<dyn mailers::Mailer> {
    ctx.shared_store
        .get::<Arc<dyn mailers::Mailer>>()
        .expect("mailer not installed")
}

/// The Slack client installed by `AuthInitializer` (tests may replace it in the shared store).
pub fn slack(ctx: &AppContext) -> Arc<dyn SlackClient> {
    ctx.shared_store
        .get::<Arc<dyn SlackClient>>()
        .expect("slack client not installed")
}
