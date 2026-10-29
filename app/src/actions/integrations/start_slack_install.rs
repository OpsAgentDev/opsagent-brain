use std::sync::Arc;

use uuid::Uuid;

use super::{configured, not_configured, redirect_uri, SlackSettings};
use crate::{
    actions::{
        billing::{BillingGate, Seat},
        uow::UnitOfWork,
    },
    adapters::slack::{AUTHORIZE_URL, BOT_SCOPES},
    error::AppResult,
};

/// The Slack consent URL carrying `state`; 503 `slack_not_configured` without client
/// credentials, 402 `plan_limit` over the tier's limits. The caller keeps `state` (in the
/// session) to check the callback against.
pub struct StartSlackInstall {
    settings: SlackSettings,
    uow: Arc<dyn UnitOfWork>,
    gate: BillingGate,
}

impl StartSlackInstall {
    pub fn new(settings: SlackSettings, uow: Arc<dyn UnitOfWork>, gate: BillingGate) -> Self {
        Self {
            settings,
            uow,
            gate,
        }
    }

    pub async fn run(&self, organisation_id: Uuid, state: &str) -> AppResult<String> {
        let seat = Seat::Integration;
        self.gate
            .require_plan_room(&*self.uow, organisation_id, seat)
            .await?;
        let s = &self.settings;
        if !configured(s) {
            return Err(not_configured());
        }
        let e = |v: &str| urlencoding::encode(v).into_owned();
        Ok(format!(
            "{AUTHORIZE_URL}?client_id={}&scope={}&redirect_uri={}&state={}",
            e(&s.client_id),
            e(BOT_SCOPES),
            e(&redirect_uri(s)),
            e(state)
        ))
    }
}
