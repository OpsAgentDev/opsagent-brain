//! Test-support adapters: swappable mailer, Slack and billing-provider cells.
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use opsagent_core::billing::{BillingProvider, BillingResult, CheckoutRequest};
use uuid::Uuid;

use crate::{
    adapters::slack::{Channel, Install, SlackClient, SlackError},
    mailers::{Mail, Mailer},
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

#[async_trait]
impl BillingProvider for Swappable<dyn BillingProvider> {
    async fn create_customer(
        &self,
        organisation_id: Uuid,
        name: &str,
        email: &str,
        idem: &str,
    ) -> BillingResult<String> {
        let b = self.get();
        b.create_customer(organisation_id, name, email, idem).await
    }

    async fn checkout_session(&self, req: &CheckoutRequest, idem: &str) -> BillingResult<String> {
        self.get().checkout_session(req, idem).await
    }

    async fn portal_session(&self, customer_id: &str, return_url: &str) -> BillingResult<String> {
        self.get().portal_session(customer_id, return_url).await
    }

    async fn set_quantity(
        &self,
        subscription_id: &str,
        quantity: i32,
        prorate: bool,
        idem: &str,
    ) -> BillingResult<()> {
        let b = self.get();
        b.set_quantity(subscription_id, quantity, prorate, idem)
            .await
    }

    async fn cancel_subscription(&self, subscription_id: &str, idem: &str) -> BillingResult<()> {
        self.get().cancel_subscription(subscription_id, idem).await
    }
}

/// The cells `assemble` wraps the mailer, Slack client and billing provider in under
/// `test-support`.
pub struct Swaps {
    pub mailer: Arc<Swappable<dyn Mailer>>,
    pub slack: Arc<Swappable<dyn SlackClient>>,
    pub billing: Arc<Swappable<dyn BillingProvider>>,
}
