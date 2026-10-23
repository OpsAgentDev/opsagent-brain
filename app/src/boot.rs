//! Wiring in one place: every action is built here, once per process, from its adapters.
use std::sync::Arc;

use opsagent_connectors::Registry;
use opsagent_core::repo::Clock;
use opsagent_ledger::{redis, Queue};
use opsagent_secrets::Kek;

use crate::{
    actions::{
        auth, connections, findings, integrations, members, orgs, recipients, resources, runs,
        uow::UnitOfWork, Actions, RateLimiter,
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
    /// Leases and per-connection claims (`opsagent_ledger::lease`).
    pub ledger_redis: redis::Client,
}

pub fn build_actions(d: &Deps) -> Actions {
    let dispatcher = Arc::new(runs::RunDispatcher::new(d.uow.clone(), d.queue.clone()));
    let full_scan = runs::FullScan::new(
        d.uow.clone(),
        d.ledger_redis.clone(),
        d.kek.clone(),
        d.registry.clone(),
        d.clock.clone(),
    );
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
                d.settings.web_base_url.clone(),
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
            dispatcher,
            scan_now: runs::ScanNow::new(d.uow.clone(), full_scan.clone(), d.clock.clone()),
            full_scan,
        },
        recipients: recipients(d),
        integrations: integrations(d),
    }
}

fn recipients(d: &Deps) -> recipients::Recipients {
    let guard = Arc::new(recipients::MailGuard::new(d.uow.clone(), d.limiter.clone()));
    recipients::Recipients {
        list_recipients: recipients::ListRecipients::new(d.uow.clone()),
        create_recipient: recipients::CreateRecipient::new(
            d.uow.clone(),
            guard.clone(),
            d.mailer.clone(),
            &d.settings.web_base_url,
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
            d.settings.unsubscribe_key(),
            d.clock.clone(),
        ),
        mail_guard: guard,
    }
}

fn integrations(d: &Deps) -> integrations::Integrations {
    integrations::Integrations {
        start_slack_install: integrations::StartSlackInstall::new(d.settings.clone()),
        finish_slack_install: integrations::FinishSlackInstall::new(
            d.uow.clone(),
            d.kek.clone(),
            d.slack.clone(),
            d.settings.clone(),
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
