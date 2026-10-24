//! Wiring in one place: every adapter and every action is built here, once per process.
use std::{sync::Arc, time::Duration};

use migration::{Migrator, MigratorTrait};
use opsagent_connectors::{aws::AwsOutbound, Registry};
use opsagent_core::repo::{Clock, SystemClock};
use opsagent_ledger::redis;
use opsagent_secrets::{CachingKek, EnvKek, Kek};
use sea_orm::{ConnectOptions, Database, DatabaseConnection};

use axum::{middleware::from_fn_with_state, Router};

use crate::{
    actions::{
        auth, connections, deliveries, findings, integrations, members, oauth, orgs, recipients,
        resources, runs, uow::UnitOfWork, Actions, ClientMetadataSource, ConnectorSource,
        RateLimiter,
    },
    adapters::{
        client_metadata::HttpClientMetadata,
        db::Pg,
        pg_queue::PgQueue,
        rate_limiter::RedisRateLimiter,
        slack::{HttpSlack, SlackClient},
    },
    config::{Config, ConnectorMode},
    controllers,
    error::{AppError, AppResult},
    jobs::{
        DeliverBriefingJob, DeliverWeeklyJob, FullScanJob, JobHandler, Scheduler, VerifyJob,
        WorkerRunner,
    },
    mailers::{self, Mailer},
    mcp, middleware,
    state::{AppState, Inner, OAuthUrls},
    tools::{self, Tool, ToolRegistry},
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
    /// Fetches Client ID Metadata Documents.
    pub client_metadata: Arc<dyn ClientMetadataSource>,
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

/// The one pool's size: `DB_MAX_CONNECTIONS`, and with a worker in the process at least one
/// connection per job in flight plus one to poll.
pub fn pool_size(c: &Config, worker: bool) -> u32 {
    let jobs = u32::try_from(c.worker_concurrency + 1).unwrap_or(u32::MAX);
    if worker {
        c.db_max_connections.max(jobs)
    } else {
        c.db_max_connections
    }
}

/// The process's one pool on `DATABASE_URL`, sized by `pool_size`.
pub async fn pool(c: &Config, worker: bool) -> AppResult<DatabaseConnection> {
    connect(c, c.db_min_connections, pool_size(c, worker), false).await
}

/// Connects the app pool (migrating when `DB_AUTO_MIGRATE`), then every adapter and action
/// over it. `worker`: the process also runs `worker(state)` (`start --worker`,
/// `--server-and-worker`).
pub async fn boot(config: Config, worker: bool) -> AppResult<AppState> {
    let db = pool(&config, worker).await?;
    if config.db_auto_migrate {
        Migrator::up(&db, None).await.map_err(internal)?;
    }
    Ok(assemble(deps(config, db).await?))
}

/// Builds every adapter over the app pool `db`; tests replace doubles before `assemble`.
/// Jobs are enqueued on the run's transaction (`Tx::queue`), so there is no queue adapter.
pub async fn deps(config: Config, db: DatabaseConnection) -> AppResult<Deps> {
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
        client_metadata: Arc::new(HttpClientMetadata),
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
        tools: Arc::new(build_tools(&deps)),
        oauth_urls: OAuthUrls::new(&deps.config.api_base_url),
        deps,
        actions,
        #[cfg(feature = "test-support")]
        swaps,
    }))
}

pub fn build_actions(d: &Deps) -> Actions {
    let urls = OAuthUrls::new(&d.config.api_base_url);
    let dispatcher = Arc::new(runs::RunDispatcher::new(d.uow.clone()));
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
            remove_member: members::RemoveMember::new(d.uow.clone(), d.clock.clone()),
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
            scheduler_tick: Arc::new(runs::SchedulerTick::new(
                d.scheduler_uow.clone(),
                dispatcher.clone(),
            )),
            dispatcher,
            scan_now: runs::ScanNow::new(d.uow.clone(), full_scan.clone(), d.clock.clone()),
            full_scan,
        },
        recipients: recipients(d, guard.clone()),
        integrations: integrations(d),
        deliveries: deliveries(d, guard),
        oauth: oauth::OAuth {
            register_client: oauth::RegisterClient::new(
                d.uow.clone(),
                d.limiter.clone(),
                d.clock.clone(),
            ),
            resolve_client: oauth::ResolveClient::new(d.uow.clone(), d.client_metadata.clone()),
            start_authorization: oauth::StartAuthorization::new(
                d.uow.clone(),
                oauth::ResolveClient::new(d.uow.clone(), d.client_metadata.clone()),
                d.limiter.clone(),
                urls.resource.clone(),
            ),
            get_consent: oauth::GetConsent::new(d.uow.clone()),
            decide_consent: oauth::DecideConsent::new(d.uow.clone(), urls.issuer.clone()),
            exchange_code: oauth::ExchangeCode::new(d.uow.clone()),
            refresh_grant: oauth::RefreshGrant::new(d.uow.clone()),
            revoke_token: oauth::RevokeToken::new(d.uow.clone()),
            list_agents: oauth::ListAgents::new(d.uow.clone()),
            revoke_agent: oauth::RevokeAgent::new(d.uow.clone()),
            authenticate_bearer: oauth::AuthenticateBearer::new(
                d.uow.clone(),
                orgs::ResolveOrgScope::new(d.uow.clone()),
            ),
            touch_grant: oauth::TouchGrant::new(d.uow.clone()),
        },
    }
}

/// Every tool, the only registry of tool names: a new tool is one file and one line here.
pub fn build_tools(d: &Deps) -> ToolRegistry {
    let scan = runs::RequestManualScan::new(
        d.uow.clone(),
        Arc::new(runs::RunDispatcher::new(d.uow.clone())),
        d.clock.clone(),
    );
    let tools: Vec<Arc<dyn Tool>> = vec![
        Arc::new(tools::ListConnectionsTool::new(
            connections::ListConnections::new(d.uow.clone()),
            runs::ListRuns::new(d.uow.clone()),
        )),
        Arc::new(tools::ListFindingsTool::new(findings::ListFindings::new(
            d.uow.clone(),
        ))),
        Arc::new(tools::GetFindingTool::new(findings::GetFinding::new(
            d.uow.clone(),
        ))),
        Arc::new(tools::ListResourcesTool::new(
            resources::ListResources::new(d.uow.clone()),
        )),
        Arc::new(tools::GetScanTool::new(runs::GetRun::new(d.uow.clone()))),
        Arc::new(tools::RunCheckTool::new(scan, d.clock.clone())),
        Arc::new(tools::GetCostAnomaliesTool::new(
            findings::ListFindings::new(d.uow.clone()),
            d.clock.clone(),
        )),
    ];
    ToolRegistry::new(tools, d.uow.clone())
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
    let slack = integrations::SlackSettings {
        client_id: d.config.slack_client_id.clone(),
        client_secret: d.config.slack_client_secret.clone(),
        api_base_url: d.config.api_base_url.clone(),
    };
    integrations::Integrations {
        start_slack_install: integrations::StartSlackInstall::new(slack.clone()),
        finish_slack_install: integrations::FinishSlackInstall::new(
            d.uow.clone(),
            d.kek.clone(),
            d.slack.clone(),
            slack,
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
        web_base_url: d.config.web_base_url.clone(),
        unsubscribe_key: d.config.unsubscribe_key().to_owned(),
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

/// The job runner with the four job handlers, the only registry of job kinds. The queue and
/// the job work share the state's one pool (`pool_size` with a worker).
pub fn worker(state: &AppState) -> WorkerRunner {
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
    let source = Arc::new(PgQueue(state.db.clone()));
    WorkerRunner::new(source, handlers, &state.config, state.clock.clone())
}

/// The scheduler loop: the state's `SchedulerTick` every 60 s.
pub fn scheduler(state: &AppState) -> Scheduler {
    Scheduler {
        tick: state.actions.runs.scheduler_tick.clone(),
        every: Duration::from_secs(60),
    }
}

/// Health, `/v1` and `/openapi.json` on the shell's middleware stack (`middleware::stack`),
/// merged with OAuth, discovery and `/mcp` (behind its bearer layer) on the public one
/// (`middleware::public_stack`).
pub fn router(state: AppState) -> AppResult<Router> {
    let routes = controllers::health::routes().merge(controllers::openapi::routes());
    #[cfg(feature = "test-support")]
    let routes = routes.merge(controllers::test_routes::routes());
    let shell = middleware::stack(routes.with_state(state.clone()), &state)?;
    let mcp = Router::new()
        .nest_service("/mcp", mcp::service(&state))
        .route_layer(from_fn_with_state(state.clone(), mcp::auth::layer));
    let public = controllers::oauth::routes()
        .with_state(state.clone())
        .merge(mcp);
    Ok(shell.merge(middleware::public_stack(public, &state)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_worker_process_gets_a_connection_per_job_plus_one() {
        let mut c = Config::from_vars(|k| (k == "APP_ENV").then(|| "test".into())).unwrap();
        (c.db_max_connections, c.worker_concurrency) = (2, 4);
        assert_eq!((pool_size(&c, false), pool_size(&c, true)), (2, 5));
        c.db_max_connections = 10;
        assert_eq!(pool_size(&c, true), 10);
    }
}
