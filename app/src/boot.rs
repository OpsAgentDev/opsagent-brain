//! Wiring in one place: every action is built here, once per process, from its adapters.
use std::sync::Arc;

use opsagent_connectors::Registry;
use opsagent_core::repo::Clock;
use opsagent_secrets::Kek;

use crate::{
    actions::{auth, uow::UnitOfWork, Actions, RateLimiter},
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
}

pub fn build_actions(d: &Deps) -> Actions {
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
    }
}
