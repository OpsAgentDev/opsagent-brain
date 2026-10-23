//! Test-support adapters: swappable mailer and Slack cells, and a queue that runs each job
//! inline as it is enqueued (what Loco's `ForegroundBlocking` mode did for tests).
use std::sync::{Arc, OnceLock, RwLock, Weak};

use async_trait::async_trait;
use opsagent_ledger::{LedgerError, NewJob, Queue};

use crate::{
    adapters::slack::{Channel, Install, SlackClient, SlackError},
    mailers::{Mail, Mailer},
    state::{AppState, Inner},
};

/// An adapter the test swaps after boot; actions hold the cell, so they see the swap.
pub struct Swappable<T: ?Sized>(RwLock<Arc<T>>);

impl<T: ?Sized> Swappable<T> {
    pub fn new(inner: Arc<T>) -> Arc<Self> {
        Arc::new(Self(RwLock::new(inner)))
    }

    pub fn set(&self, inner: Arc<T>) {
        *self.0.write().unwrap() = inner;
    }

    fn get(&self) -> Arc<T> {
        self.0.read().unwrap().clone()
    }
}

#[async_trait]
impl Mailer for Swappable<dyn Mailer> {
    async fn send(&self, mail: Mail) -> Result<(), String> {
        self.get().send(mail).await
    }
}

#[async_trait]
impl SlackClient for Swappable<dyn SlackClient> {
    async fn oauth_access(
        &self,
        client_id: &str,
        client_secret: &str,
        code: &str,
        redirect_uri: &str,
    ) -> Result<Install, SlackError> {
        let s = self.get();
        s.oauth_access(client_id, client_secret, code, redirect_uri)
            .await
    }

    async fn channels(&self, token: &str) -> Result<Vec<Channel>, SlackError> {
        self.get().channels(token).await
    }

    async fn revoke(&self, token: &str) -> Result<(), SlackError> {
        self.get().revoke(token).await
    }

    async fn post_message(
        &self,
        token: &str,
        channel: &str,
        text: &str,
        client_msg_id: &str,
    ) -> Result<String, SlackError> {
        let s = self.get();
        s.post_message(token, channel, text, client_msg_id).await
    }
}

/// The cells `assemble` wraps the mailer and Slack client in under `test-support`.
pub struct Swaps {
    pub mailer: Arc<Swappable<dyn Mailer>>,
    pub slack: Arc<Swappable<dyn SlackClient>>,
}

/// Runs each job inline on the state it is bound to, returning the job's error as the
/// enqueue error. Holds the state weakly: a strong reference would be a cycle
/// (state -> actions -> dispatcher -> queue -> state) and leak every test's pools.
#[derive(Default)]
pub struct InlineQueue(OnceLock<Weak<Inner>>);

impl InlineQueue {
    pub fn bind(&self, state: &AppState) {
        let _ = self.0.set(Arc::downgrade(&state.0));
    }
}

#[async_trait]
impl Queue for InlineQueue {
    async fn enqueue(&self, job: NewJob) -> opsagent_ledger::Result<()> {
        let state = self.0.get().and_then(Weak::upgrade);
        let state = state.ok_or_else(|| LedgerError::Storage("queue not bound".into()))?;
        crate::workers::perform(&state.actions, job.kind, job.run_id)
            .await
            .map_err(|e| LedgerError::Storage(e.to_string()))
    }
}
