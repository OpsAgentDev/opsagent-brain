//! Wiring in one place: every adapter and every action is built here, once per process.
use std::{sync::Arc, time::Duration};

use migration::{Migrator, MigratorTrait};
use opsagent_connectors::{aws::AwsOutbound, Registry};
use opsagent_core::repo::{Clock, SystemClock};
use opsagent_ledger::{redis, Queue};
use opsagent_secrets::{CachingKek, EnvKek, Kek};
use sea_orm::{ConnectOptions, Database, DatabaseConnection};

use axum::Router;

use crate::{
    actions::{
        auth, connections, deliveries, findings, integrations, members, orgs, recipients,
        resources, runs, uow::UnitOfWork, Actions, ConnectorSource, RateLimiter,
    },
    adapters::{
        db::Pg,
        pg_queue::PgQueue,
        rate_limiter::RedisRateLimiter,
        slack::{HttpSlack, SlackClient},
    },
    config::{Config, ConnectorMode},
    controllers,
    error::{AppError, AppResult},
    jobs::{
        DeliverBriefingJob, DeliverWeeklyJob, FullScanJob, JobHandler, VerifyJob, WorkerRunner,
    },
    mailers::{self, Mailer},
    middleware,
    state::{AppState, Inner},
};

/// security.md: unwrapped DEKs stay in memory for at most 10 minutes.
const DEK_TTL: Duration = Duration::from_secs(600);

/// The adapters actions are built from.
#[derive(Clone)]
pub struct Deps {
    pub config: Config,
    pub db: DatabaseConnection,
    pub uow: Arc<dyn UnitOfWork>,
    /// The scheduler tick's own 2-connection pool: one connection holds the advisory-lock
    /// transaction for the whole tick, the other does the per-schedule work.
    pub scheduler_uow: Arc<dyn UnitOfWork>,
    /// Leases and per-connection claims (`opsagent_ledger::lease`), and the rate limiter.
    pub redis: redis::Client,
    pub limiter: Arc<dyn RateLimiter>,
    pub kek: Arc<dyn Kek>,
    pub registry: Registry,
    pub mailer: Arc<dyn Mailer>,
    pub slack: Arc<dyn SlackClient>,
    pub clock: Arc<dyn Clock>,
    pub queue: Arc<dyn Queue>,
}

fn internal(e: impl std::fmt::Display) -> AppError {
    AppError::Internal(e.to_string())
}

async fn connect(c: &Config, min: u32, max: u32, lazy: bool) -> AppResult<DatabaseConnection> {
    let mut opts = ConnectOptions::new(c.database_url.clone());
    opts.min_connections(min)
        .max_connections(max)
        .connect_timeout(Duration::from_millis(c.db_connect_timeout_ms))
        .idle_timeout(Duration::from_millis(c.db_idle_timeout_ms))
        .sqlx_logging(c.db_logging)
        .connect_lazy(lazy);
    Database::connect(opts).await.map_err(internal)
}

/// The app pool: `DB_MIN_CONNECTIONS`..`DB_MAX_CONNECTIONS` on `DATABASE_URL`.
pub async fn pool(c: &Config) -> AppResult<DatabaseConnection> {
    connect(c, c.db_min_connections, c.db_max_connections, false).await
}

/// Connects the app pool (migrating when `DB_AUTO_MIGRATE`), then `boot_on` it.
pub async fn boot(config: Config, queue: Arc<dyn Queue>) -> AppResult<AppState> {
    let db = pool(&config).await?;
    if config.db_auto_migrate {
        Migrator::up(&db, None).await.map_err(internal)?;
    }
    boot_on(config, db, queue).await
}

/// Every adapter over the app pool `db`, then the actions. `queue` is passed in while
/// Loco's queue needs its `AppContext` (Task 18).
pub async fn boot_on(
    config: Config,
    db: DatabaseConnection,
    queue: Arc<dyn Queue>,
) -> AppResult<AppState> {
    Ok(assemble(deps(config, db, queue).await?))
}

/// Builds every adapter over the app pool `db`; tests replace doubles before `assemble`.
pub async fn deps(
    config: Config,
    db: DatabaseConnection,
    queue: Arc<dyn Queue>,
) -> AppResult<Deps> {
    // Lazy: only the scheduler process ever ticks.
    let scheduler = connect(&config, 0, 2, true).await?;
    let redis = redis::Client::open(config.redis_url.as_str()).map_err(internal)?;
    let kek: Arc<dyn Kek> = Arc::new(CachingKek::new(
        EnvKek::from_env().map_err(internal)?,
        DEK_TTL,
    ));
    let outbound = AwsOutbound {
        principal_arn: config.aws_outbound_role_arn.clone(),
        ..Default::default()
    };
    let registry = Registry::new(outbound, config.connectors == ConnectorMode::Fake);
    let slack = HttpSlack::new(&config.slack_api_base_url)
        .map_err(|_| internal("slack: HTTP client could not be built"))?;
    Ok(Deps {
        mailer: mailers::from_config(&config).map_err(internal)?,
        config,
        uow: Arc::new(Pg::new(db.clone())),
        db,
        scheduler_uow: Arc::new(Pg::new(scheduler)),
        limiter: Arc::new(RedisRateLimiter::new(redis.clone())),
        redis,
        kek,
        registry,
        slack: Arc::new(slack),
        clock: Arc::new(SystemClock),
        queue,
    })
}

/// The state over `deps`, with every action built from them, once. Under `test-support` the
/// mailer and Slack client sit in cells `AppState::set_mailer`/`set_slack` swap.
pub fn assemble(#[allow(unused_mut)] mut deps: Deps) -> AppState {
    #[cfg(feature = "test-support")]
    let swaps = {
        use crate::adapters::test_doubles::{Swappable, Swaps};
        let swaps = Swaps {
            mailer: Swappable::new(deps.mailer.clone()),
            slack: Swappable::new(deps.slack.clone()),
        };
        deps.mailer = swaps.mailer.clone();
        deps.slack = swaps.slack.clone();
        swaps
    };
    let actions = Arc::new(build_actions(&deps));
    AppState(Arc::new(Inner {
        deps,
        actions,
        #[cfg(feature = "test-support")]
        swaps,
    }))
}

pub fn build_actions(d: &Deps) -> Actions {
    let dispatcher = Arc::new(runs::RunDispatcher::new(d.uow.clone(), d.queue.clone()));
    let connectors: Arc<dyn ConnectorSource> = Arc::new(d.registry.clone());
    let full_scan = runs::FullScan::new(
        d.uow.clone(),
        d.redis.clone(),
        d.kek.clone(),
        connectors.clone(),
        d.clock.clone(),
    );
    // One guard for recipient confirms and delivery mail.
    let guard = Arc::new(recipients::MailGuard::new(d.uow.clone(), d.limiter.clone()));
    Actions {
        auth: auth::Auth {
            request_magic_link: auth::RequestMagicLink::new(
                d.uow.clone(),
                d.limiter.clone(),
                d.mailer.clone(),
                d.config.web_base_url.clone(),
                d.clock.clone(),
            ),
            redeem_magic_link: auth::RedeemMagicLink::new(d.uow.clone(), d.clock.clone()),
            sign_in_github: auth::SignInGithub::new(d.uow.clone()),
            current_user: auth::CurrentUser::new(d.uow.clone()),
        },
        orgs: orgs::Orgs {
            resolve_scope: orgs::ResolveOrgScope::new(d.uow.clone()),
            create_org: orgs::CreateOrg::new(d.uow.clone(), d.kek.clone(), d.limiter.clone()),
            list_orgs: orgs::ListOrgs::new(d.uow.clone()),
            get_org: orgs::GetOrg,
            update_org: orgs::UpdateOrg::new(d.uow.clone()),
            delete_org: orgs::DeleteOrg::new(d.uow.clone(), d.clock.clone()),
            is_owner_anywhere: orgs::IsOwnerAnywhere::new(d.uow.clone()),
        },
        members: members::Members {
            list_members: members::ListMembers::new(d.uow.clone()),
            invite_member: members::InviteMember::new(
                d.uow.clone(),
                d.mailer.clone(),
                d.config.web_base_url.clone(),
                d.clock.clone(),
            ),
            accept_invite: members::AcceptInvite::new(d.uow.clone(), d.clock.clone()),
            remove_member: members::RemoveMember::new(d.uow.clone()),
        },
        findings: findings::Findings {
            list_findings: findings::ListFindings::new(d.uow.clone()),
            get_finding: findings::GetFinding::new(d.uow.clone()),
            change_finding_status: findings::ChangeFindingStatus::new(
                d.uow.clone(),
                d.clock.clone(),
            ),
            report_explanation: findings::ReportExplanation::new(d.uow.clone()),
        },
        resources: resources::Resources {
            list_resources: resources::ListResources::new(d.uow.clone()),
        },
        connections: connections::Connections {
            create_connection: connections::CreateConnection::new(
                d.uow.clone(),
                d.kek.clone(),
                d.registry.clone(),
            ),
            list_connections: connections::ListConnections::new(d.uow.clone()),
            get_connection: connections::GetConnection::new(d.uow.clone()),
            update_connection: connections::UpdateConnection::new(d.uow.clone(), d.clock.clone()),
            request_verify: connections::RequestVerify::new(
                d.uow.clone(),
                d.kek.clone(),
                dispatcher.clone(),
                d.clock.clone(),
            ),
            disconnect_connection: connections::DisconnectConnection::new(d.uow.clone()),
        },
        runs: runs::Runs {
            request_manual_scan: runs::RequestManualScan::new(
                d.uow.clone(),
                dispatcher.clone(),
                d.clock.clone(),
            ),
            list_runs: runs::ListRuns::new(d.uow.clone()),
            get_run: runs::GetRun::new(d.uow.clone()),
            verify_connection: runs::VerifyConnection::new(
                d.uow.clone(),
                d.redis.clone(),
                d.kek.clone(),
                connectors,
                dispatcher.clone(),
                d.clock.clone(),
            ),
            scheduler_tick: runs::SchedulerTick::new(d.scheduler_uow.clone(), dispatcher.clone()),
            dispatcher,
            scan_now: runs::ScanNow::new(d.uow.clone(), full_scan.clone(), d.clock.clone()),
            full_scan,
        },
        recipients: recipients(d, guard.clone()),
        integrations: integrations(d),
        deliveries: deliveries(d, guard),
    }
}

fn recipients(d: &Deps, guard: Arc<recipients::MailGuard>) -> recipients::Recipients {
    recipients::Recipients {
        list_recipients: recipients::ListRecipients::new(d.uow.clone()),
        create_recipient: recipients::CreateRecipient::new(
            d.uow.clone(),
            guard.clone(),
            d.mailer.clone(),
            &d.config.web_base_url,
            d.clock.clone(),
        ),
        delete_recipient: recipients::DeleteRecipient::new(d.uow.clone()),
        confirm_recipient: recipients::ConfirmRecipient::new(
            d.uow.clone(),
            guard.clone(),
            d.clock.clone(),
        ),
        unsubscribe: recipients::Unsubscribe::new(
            d.uow.clone(),
            d.config.unsubscribe_key(),
            d.clock.clone(),
        ),
        mail_guard: guard,
    }
}

fn integrations(d: &Deps) -> integrations::Integrations {
    integrations::Integrations {
        start_slack_install: integrations::StartSlackInstall::new(d.config.clone()),
        finish_slack_install: integrations::FinishSlackInstall::new(
            d.uow.clone(),
            d.kek.clone(),
            d.slack.clone(),
            d.config.clone(),
        ),
        list_slack_channels: integrations::ListSlackChannels::new(
            d.uow.clone(),
            d.kek.clone(),
            d.slack.clone(),
            d.clock.clone(),
        ),
        list_integrations: integrations::ListIntegrations::new(d.uow.clone()),
        delete_integration: integrations::DeleteIntegration::new(
            d.uow.clone(),
            d.kek.clone(),
            d.slack.clone(),
        ),
    }
}

fn deliveries(d: &Deps, guard: Arc<recipients::MailGuard>) -> deliveries::Deliveries {
    let kit = deliveries::Kit {
        uow: d.uow.clone(),
        redis: d.redis.clone(),
        kek: d.kek.clone(),
        mailer: d.mailer.clone(),
        slack: d.slack.clone(),
        guard,
        clock: d.clock.clone(),
        settings: d.config.clone(),
    };
    deliveries::Deliveries {
        list_deliveries: deliveries::ListDeliveries::new(d.uow.clone()),
        get_delivery: deliveries::GetDelivery::new(d.uow.clone()),
        preview_briefing: deliveries::PreviewBriefing::new(
            d.uow.clone(),
            d.config.web_base_url.clone(),
            d.clock.clone(),
        ),
        deliver_briefing: deliveries::DeliverBriefing::new(kit.clone()),
        deliver_weekly: deliveries::DeliverWeekly::new(kit.clone()),
        deliver_briefing_now: deliveries::DeliverBriefingNow::new(kit),
    }
}

/// The job runner with the four job handlers, the only registry of job kinds, on its own pool
/// of `WORKER_CONCURRENCY + 1` connections (one per job in flight, one to poll).
pub async fn worker(state: &AppState) -> AppResult<WorkerRunner> {
    let c = &state.config;
    let max = u32::try_from(c.worker_concurrency + 1).map_err(internal)?;
    let pool = connect(c, 0, max, false).await?;
    let (runs, deliveries) = (&state.actions.runs, &state.actions.deliveries);
    let handlers: Vec<Arc<dyn JobHandler>> = vec![
        Arc::new(VerifyJob(Arc::new(runs.verify_connection.clone()))),
        Arc::new(FullScanJob(Arc::new(runs.full_scan.clone()))),
        Arc::new(DeliverBriefingJob(Arc::new(
            deliveries.deliver_briefing.clone(),
        ))),
        Arc::new(DeliverWeeklyJob(Arc::new(
            deliveries.deliver_weekly.clone(),
        ))),
    ];
    let source = Arc::new(PgQueue(pool));
    Ok(WorkerRunner::new(source, handlers, c, state.clock.clone()))
}

/// Health, `/v1` and `/openapi.json` on the shell's middleware stack (`middleware::stack`).
pub fn router(state: AppState) -> AppResult<Router> {
    let routes = controllers::health::routes().merge(controllers::openapi::routes());
    #[cfg(feature = "test-support")]
    let routes = routes.merge(controllers::test_routes::routes());
    middleware::stack(routes.with_state(state.clone()), &state)
}
