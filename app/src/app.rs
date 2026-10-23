use async_trait::async_trait;
use axum::Router as AxumRouter;
use loco_rs::{
    app::{AppContext, Hooks},
    bgworker::{BackgroundWorker, Queue},
    boot::{create_app, BootResult, StartMode},
    config::Config,
    controller::{middleware::MiddlewareLayer, AppRoutes},
    environment::Environment,
    task::Tasks,
    Result,
};
use migration::Migrator;
use std::{path::Path, sync::Arc};

use crate::{
    actions::Actions,
    adapters::loco_queue::LocoQueue,
    boot,
    config::Config as AppConfig,
    logging::init_tracing,
    state::AppState,
    tasks::{
        deliver_briefing::DeliverBriefingNow, openapi_dump::OpenapiDump, scan_now::ScanNow,
        scheduler_tick::SchedulerTick,
    },
    workers::{
        full_scan::FullScanWorker, verify::VerifyWorker, DeliverBriefingWorker, DeliverWeeklyWorker,
    },
};

/// The state `boot` built, from the shared store.
pub fn state(ctx: &AppContext) -> Result<AppState> {
    ctx.shared_store
        .get::<AppState>()
        .ok_or_else(|| loco_rs::Error::string("app state not installed"))
}

/// The process-wide KEK (with the DEK cache).
pub fn kek(ctx: &AppContext) -> Result<Arc<dyn opsagent_secrets::Kek>> {
    Ok(state(ctx)?.kek.clone())
}

/// The actions, built once by `boot`.
pub fn actions(ctx: &AppContext) -> Result<Arc<Actions>> {
    Ok(state(ctx)?.actions.clone())
}

#[cfg(feature = "test-support")]
/// Test seam until Task 15's `TestApp` hands its doubles to `boot`: replaces the state with
/// `f` applied to its adapters, so every action is rebuilt over them.
pub fn replace_deps(ctx: &AppContext, f: impl FnOnce(&mut boot::Deps)) -> Result<()> {
    let mut deps = state(ctx)?.deps.clone();
    f(&mut deps);
    ctx.shared_store.insert(boot::assemble(deps));
    Ok(())
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
        let queue = Arc::new(LocoQueue(ctx.clone()));
        // shortcut: Loco owns the app pool and migrations while it boots the process, so the
        // state reuses `ctx.db` (one pool, as before); `boot` connects its own from Task 16.
        let state = boot::boot_on(config, ctx.db.clone(), queue)
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

    /// shortcut: Loco still runs the process until Task 15's `main`, so it serves our router
    /// whole: its own routes and middleware are emptied (nothing doubled, no `x-powered-by` or
    /// etag) and the router it built is empty, so ours replaces it. Removed with Loco in Task 15.
    async fn after_routes(_router: AxumRouter, ctx: &AppContext) -> Result<AxumRouter> {
        boot::router(state(ctx)?).map_err(|e| loco_rs::Error::string(&e.to_string()))
    }

    fn middlewares(_ctx: &AppContext) -> Vec<Box<dyn MiddlewareLayer>> {
        vec![]
    }

    fn routes(_ctx: &AppContext) -> AppRoutes {
        AppRoutes::empty()
    }

    async fn connect_workers(ctx: &AppContext, queue: &Queue) -> Result<()> {
        queue.register(VerifyWorker::build(ctx)).await?;
        queue.register(FullScanWorker::build(ctx)).await?;
        queue.register(DeliverBriefingWorker::build(ctx)).await?;
        queue.register(DeliverWeeklyWorker::build(ctx)).await
    }

    fn register_tasks(tasks: &mut Tasks) {
        tasks.register(OpenapiDump);
        tasks.register(ScanNow);
        tasks.register(DeliverBriefingNow);
        tasks.register(SchedulerTick);
    }

    async fn truncate(_ctx: &AppContext) -> Result<()> {
        Ok(())
    }

    async fn seed(_ctx: &AppContext, _base: &Path) -> Result<()> {
        Ok(())
    }
}
