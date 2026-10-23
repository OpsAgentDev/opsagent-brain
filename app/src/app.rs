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
use opsagent_connectors::{aws::AwsOutbound, Registry};
use opsagent_core::repo::SystemClock;
use opsagent_secrets::{CachingKek, EnvKek, Kek};
use std::{path::Path, sync::Arc, time::Duration};

use crate::{
    actions::Actions,
    adapters::{db::Pg, loco_queue::LocoQueue},
    boot::{build_actions, Deps},
    controllers,
    middleware::{self, AuthInitializer},
    settings::Settings,
    tasks::{
        deliver_briefing::DeliverBriefingNow, openapi_dump::OpenapiDump, scan_now::ScanNow,
        scheduler_tick::SchedulerTick,
    },
    workers::{
        deliver_briefing::DeliverBriefingWorker, deliver_weekly::DeliverWeeklyWorker,
        full_scan::FullScanWorker, verify::VerifyWorker,
    },
};

/// security.md: unwrapped DEKs stay in memory for at most 10 minutes.
const DEK_TTL: Duration = Duration::from_secs(600);

/// `OPSAGENT_CONNECTORS`: `fake` serves every provider from fixtures (tests, local runs) and
/// is refused in production; `aws` (the default) uses the real connectors.
fn fake_connectors(value: Option<&str>, production: bool) -> Result<bool> {
    match value.unwrap_or("aws") {
        "fake" if production => Err(loco_rs::Error::string(
            "OPSAGENT_CONNECTORS=fake is not allowed in production",
        )),
        "fake" => Ok(true),
        "aws" => Ok(false),
        other => Err(loco_rs::Error::string(&format!(
            "OPSAGENT_CONNECTORS must be aws or fake, got {other}"
        ))),
    }
}

/// The process-wide KEK (with the DEK cache), installed at boot.
pub fn kek(ctx: &AppContext) -> Result<Arc<dyn Kek>> {
    ctx.shared_store
        .get::<Arc<dyn Kek>>()
        .ok_or_else(|| loco_rs::Error::string("KEK not installed"))
}

/// The connector registry, installed at boot.
pub fn registry(ctx: &AppContext) -> Result<Registry> {
    ctx.shared_store
        .get::<Registry>()
        .ok_or_else(|| loco_rs::Error::string("connector registry not installed"))
}

/// Builds every action from the installed adapters and stores `Arc<Actions>`. Tests that
/// replace an adapter in the shared store (the mailer) call it again.
pub fn install_actions(ctx: &AppContext) -> Result<()> {
    let deps = Deps {
        uow: Arc::new(Pg::new(ctx.db.clone())),
        limiter: middleware::rate_limiter(ctx),
        kek: kek(ctx)?,
        registry: registry(ctx)?,
        mailer: middleware::mailer(ctx),
        slack: middleware::slack(ctx),
        clock: Arc::new(SystemClock),
        settings: Settings::get(ctx),
        queue: Arc::new(LocoQueue(ctx.clone())),
    };
    ctx.shared_store.insert(Arc::new(build_actions(&deps)));
    Ok(())
}

/// The actions, installed at boot.
pub fn actions(ctx: &AppContext) -> Result<Arc<Actions>> {
    ctx.shared_store
        .get::<Arc<Actions>>()
        .ok_or_else(|| loco_rs::Error::string("actions not installed"))
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

    /// Builds the adapters every mode (server, workers, tasks) shares, once.
    async fn after_context(ctx: AppContext) -> Result<AppContext> {
        let env_kek = EnvKek::from_env().map_err(|e| loco_rs::Error::string(&e.to_string()))?;
        let kek: Arc<dyn Kek> = Arc::new(CachingKek::new(env_kek, DEK_TTL));
        ctx.shared_store.insert(kek);
        let production = ctx.environment == Environment::Production;
        let fake = fake_connectors(
            std::env::var("OPSAGENT_CONNECTORS").ok().as_deref(),
            production,
        )?;
        let outbound = AwsOutbound {
            principal_arn: std::env::var("OPSAGENT_AWS_OUTBOUND_ROLE_ARN").ok(),
            ..Default::default()
        };
        ctx.shared_store.insert(Registry::new(outbound, fake));
        middleware::install_adapters(&ctx)?;
        install_actions(&ctx)?;
        Ok(ctx)
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

#[cfg(test)]
mod tests {
    use super::fake_connectors;

    #[test]
    fn production_refuses_fake_connectors() {
        assert!(fake_connectors(Some("fake"), true).is_err());
        assert!(fake_connectors(Some("fake"), false).unwrap());
        assert!(!fake_connectors(Some("aws"), true).unwrap());
        assert!(!fake_connectors(None, true).unwrap());
        assert!(fake_connectors(Some("bogus"), false).is_err());
    }
}
