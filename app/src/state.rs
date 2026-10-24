//! `AppState`: the process-wide adapters and the actions built from them, once, by `boot`.
use std::{ops::Deref, sync::Arc};

use crate::{actions::Actions, boot::Deps};

#[derive(Clone)]
pub struct AppState(pub(crate) Arc<Inner>);

/// `state.config`, `state.db`, `state.kek`, … read through to `Deps`.
pub struct Inner {
    pub deps: Deps,
    pub actions: Arc<Actions>,
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
