use async_trait::async_trait;
use axum::Router as AxumRouter;
use loco_rs::{
    app::{AppContext, Hooks, Initializer},
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
    boot::{self, Deps},
    config::{init_tracing, Config as AppConfig},
    controllers,
    middleware::{self, AuthInitializer},
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

/// Test seam until Task 15's `TestApp` hands its doubles to `boot`: replaces the state with
/// `f` applied to its adapters, so every action is rebuilt over them.
pub fn replace_deps(ctx: &AppContext, f: impl FnOnce(&mut Deps)) -> Result<()> {
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
    /// resolved the environment (and forces `test` under its test harness), so it wins over
    /// `APP_ENV`.
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
        Ok(true)
    }

    async fn initializers(_ctx: &AppContext) -> Result<Vec<Box<dyn Initializer>>> {
        Ok(vec![Box::new(AuthInitializer)])
    }

    /// `/v1` and `/openapi.json` come from the `utoipa-axum` router so every route is in the
    /// OpenAPI document. Merged here (not in `after_routes`) so Loco's middleware stack wraps them.
    async fn before_routes(_ctx: &AppContext) -> Result<AxumRouter<AppContext>> {
        Ok(controllers::openapi::routes())
    }

    fn middlewares(ctx: &AppContext) -> Vec<Box<dyn MiddlewareLayer>> {
        middleware::request_span::stack(ctx)
    }

    fn routes(_ctx: &AppContext) -> AppRoutes {
        AppRoutes::with_default_routes().add_route(controllers::health::routes())
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
