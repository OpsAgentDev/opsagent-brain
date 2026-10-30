//! `AppState`: the process-wide adapters and the actions built from them, once, by `boot`.
use std::{ops::Deref, sync::Arc};

use crate::{
    actions::{ai::ChatTurn, Actions},
    boot::Deps,
    tools::{PromptRegistry, ResourceRegistry, ToolRegistry},
};

/// The authorisation server's issuer and the protected resource, from `APP_BASE_URL`.
#[derive(Clone, Debug)]
pub struct OAuthUrls {
    pub issuer: String,
    pub resource: String,
}

impl OAuthUrls {
    pub fn new(api_base_url: &str) -> Self {
        let issuer = api_base_url.trim_end_matches('/').to_owned();
        Self {
            resource: format!("{issuer}/mcp"),
            issuer,
        }
    }
}

#[derive(Clone)]
pub struct AppState(pub(crate) Arc<Inner>);

/// `state.config`, `state.db`, `state.kek`, … read through to `Deps`.
pub struct Inner {
    pub deps: Deps,
    pub oauth_urls: OAuthUrls,
    pub actions: Arc<Actions>,
    pub tools: Arc<ToolRegistry>,
    /// Chat turns run tools, so they are built after the registry.
    pub chat: Arc<ChatTurn>,
    pub resources: Arc<ResourceRegistry>,
    pub prompts: Arc<PromptRegistry>,
    #[cfg(feature = "test-support")]
    pub swaps: crate::adapters::test_doubles::Swaps,
}

#[cfg(feature = "test-support")]
impl AppState {
    /// Swaps the mailer every action sends through.
    pub fn set_mailer(&self, m: Arc<dyn crate::mailers::Mailer>) {
        self.swaps.mailer.set(m);
    }

    /// Swaps the Slack client every action calls.
    pub fn set_slack(&self, s: Arc<dyn crate::adapters::slack::SlackClient>) {
        self.swaps.slack.set(s);
    }

    /// Swaps the billing provider every action calls.
    pub fn set_billing(&self, b: Arc<dyn opsagent_core::billing::BillingProvider>) {
        self.swaps.billing.set(b);
    }

    /// Swaps the model provider every AI call goes through (both providers).
    pub fn set_models(&self, m: Arc<dyn opsagent_core::model::ModelProvider>) {
        self.swaps.models.set(m);
    }
}

impl Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl Deref for Inner {
    type Target = Deps;
    fn deref(&self) -> &Deps {
        &self.deps
    }
}
