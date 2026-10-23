//! `AppState`: the process-wide adapters and the actions built from them, once, by `boot`.
use std::{ops::Deref, sync::Arc};

use crate::{actions::Actions, boot::Deps};

#[derive(Clone)]
pub struct AppState(pub(crate) Arc<Inner>);

/// `state.config`, `state.db`, `state.kek`, … read through to `Deps`.
pub struct Inner {
    pub deps: Deps,
    pub actions: Arc<Actions>,
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
