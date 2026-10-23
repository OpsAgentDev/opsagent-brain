use async_trait::async_trait;
use axum::Router as AxumRouter;
use loco_rs::{
    app::{AppContext, Hooks},
    bgworker::Queue,
    boot::{create_app, BootResult, StartMode},
    config::Config,
    controller::{middleware::MiddlewareLayer, AppRoutes},
    environment::Environment,
    task::Tasks,
    Result,
};
use migration::Migrator;
use std::path::Path;

use crate::{boot, config::Config as AppConfig, logging::init_tracing, state::AppState};

/// The state `boot` built, from the shared store.
pub fn state(ctx: &AppContext) -> Result<AppState> {
    ctx.shared_store
        .get::<AppState>()
        .ok_or_else(|| loco_rs::Error::string("app state not installed"))
}

pub struct App;
#[async_trait]
impl Hooks for App {
    fn app_name() -> &'static str {
        env!("CARGO_CRATE_NAME")
    }

    fn app_version() -> String {
        format!(
            "{} ({})",
            env!("CARGO_PKG_VERSION"),
            option_env!("BUILD_SHA")
                .or(option_env!("GITHUB_SHA"))
                .unwrap_or("dev")
        )
    }

    async fn boot(
        mode: StartMode,
        environment: &Environment,
        config: Config,
    ) -> Result<BootResult> {
        create_app::<Self, Migrator>(mode, environment, config).await
    }

    /// Builds the state every mode (server, workers, tasks) shares, once. Loco has already
    /// resolved the environment (and forces `test` under its test harness), so in this
    /// transitional wiring Loco's environment overrides `APP_ENV`: deploys keep setting
    /// `LOCO_ENV` until Task 14's `main` reads `APP_ENV` itself.
    async fn after_context(ctx: AppContext) -> Result<AppContext> {
        let env = ctx.environment.to_string();
        let vars = |k: &str| match k {
            "APP_ENV" => Some(env.clone()),
            _ => std::env::var(k).ok(),
        };
        let config =
            AppConfig::from_vars(vars).map_err(|e| loco_rs::Error::string(&e.to_string()))?;
        let state = boot::boot(config, false)
            .await
            .map_err(|e| loco_rs::Error::string(&e.to_string()))?;
        ctx.shared_store.insert(state);
        Ok(ctx)
    }

    /// Our subscriber instead of Loco's (same filter and formats).
    fn init_logger(ctx: &AppContext) -> Result<bool> {
        init_tracing(&state(ctx)?.config);
        crate::config::warn_if_loco_env();
        Ok(true)
    }

    /// shortcut: Loco still runs `start --server-and-worker` until Task 18, so it serves our
    /// router whole: its own routes and middleware are emptied (nothing doubled, no
    /// `x-powered-by` or etag) and the router it built is empty, so ours replaces it.
    async fn after_routes(_router: AxumRouter, ctx: &AppContext) -> Result<AxumRouter> {
        boot::router(state(ctx)?).map_err(|e| loco_rs::Error::string(&e.to_string()))
    }

    fn middlewares(_ctx: &AppContext) -> Vec<Box<dyn MiddlewareLayer>> {
        vec![]
    }

    fn routes(_ctx: &AppContext) -> AppRoutes {
        AppRoutes::empty()
    }

    /// Required by `Hooks`; jobs run on our `WorkerRunner`, never Loco's queue.
    async fn connect_workers(_ctx: &AppContext, _queue: &Queue) -> Result<()> {
        Ok(())
    }

    /// Required by `Hooks`; tasks run through our `cli`, never Loco's.
    fn register_tasks(_tasks: &mut Tasks) {}

    async fn truncate(_ctx: &AppContext) -> Result<()> {
        Ok(())
    }

    async fn seed(_ctx: &AppContext, _base: &Path) -> Result<()> {
        Ok(())
    }
}
