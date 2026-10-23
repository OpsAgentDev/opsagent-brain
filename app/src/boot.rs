//! Wiring in one place: every action is built here, once per process, from its adapters.
use std::sync::Arc;

use opsagent_connectors::Registry;
use opsagent_core::repo::Clock;
use opsagent_ledger::{redis, Queue};
use opsagent_secrets::Kek;

use crate::{
    actions::{
        auth, connections, findings, resources, runs, uow::UnitOfWork, Actions, RateLimiter,
    },
    adapters::slack::SlackClient,
    mailers::Mailer,
    settings::Settings,
};

/// The adapters actions are built from.
pub struct Deps {
    pub uow: Arc<dyn UnitOfWork>,
    pub limiter: Arc<dyn RateLimiter>,
    pub kek: Arc<dyn Kek>,
    pub registry: Registry,
    pub mailer: Arc<dyn Mailer>,
    pub slack: Arc<dyn SlackClient>,
    pub clock: Arc<dyn Clock>,
    pub settings: Settings,
    pub queue: Arc<dyn Queue>,
    /// Lease locks for run workers.
    pub ledger_redis: redis::Client,
    /// The scheduler tick opens its own small pool on it.
    pub db_url: String,
}

pub fn build_actions(d: &Deps) -> Actions {
    let dispatcher = Arc::new(runs::RunDispatcher::new(d.uow.clone(), d.queue.clone()));
    Actions {
        auth: auth::Auth {
            request_magic_link: auth::RequestMagicLink::new(
                d.uow.clone(),
                d.limiter.clone(),
                d.mailer.clone(),
                d.settings.web_base_url.clone(),
                d.clock.clone(),
            ),
            redeem_magic_link: auth::RedeemMagicLink::new(d.uow.clone(), d.clock.clone()),
            sign_in_github: auth::SignInGithub::new(d.uow.clone()),
            current_user: auth::CurrentUser::new(d.uow.clone()),
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
                d.ledger_redis.clone(),
                d.kek.clone(),
                Arc::new(d.registry.clone()),
                dispatcher.clone(),
                d.clock.clone(),
            ),
            scheduler_tick: runs::SchedulerTick::new(d.db_url.clone(), dispatcher.clone()),
            dispatcher,
        },
    }
}
