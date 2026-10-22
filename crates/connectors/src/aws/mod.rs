//! AWS connector. Spec: docs/tech-spec/aws-connection.md.

pub mod client;
pub mod policy_diff;
pub mod verify;

pub use client::AwsOutbound;

use crate::{
    CallContext, Capability, Connector, ConnectorError, CostRow, Credentials, MetricPoint,
    MetricQuery, Result, Scope, VerifyOutcome,
};
use async_trait::async_trait;
use aws_config::SdkConfig;
use opsagent_core::resource::{Provider, Resource};
use std::collections::BTreeSet;
use tokio::sync::OnceCell;

pub struct AwsConnector {
    outbound: AwsOutbound,
    base: OnceCell<SdkConfig>,
}

impl AwsConnector {
    pub fn new(outbound: AwsOutbound) -> Self {
        Self {
            outbound,
            base: OnceCell::new(),
        }
    }

    /// Outbound config, loaded on first use so `registry` can stay synchronous.
    async fn base(&self) -> &SdkConfig {
        self.base
            .get_or_init(|| client::load_base(&self.outbound))
            .await
    }
}

fn aws_role(creds: &Credentials) -> Result<(&str, &str, bool, &CallContext)> {
    match creds {
        Credentials::AwsRole {
            role_arn,
            external_id,
            terraform_state,
            context,
        } => Ok((role_arn, external_id, *terraform_state, context)),
        _ => Err(ConnectorError::InvalidCredentials(
            "aws connector needs Credentials::AwsRole".into(),
        )),
    }
}

#[async_trait]
impl Connector for AwsConnector {
    fn provider(&self) -> Provider {
        Provider::Aws
    }

    fn capabilities(&self) -> BTreeSet<Capability> {
        use Capability::*;
        [
            Inventory,
            CostDaily,
            IamReport,
            PublicAccess,
            Backups,
            Logging,
            Gpu,
        ]
        .into()
    }

    async fn verify(&self, creds: &Credentials) -> Result<VerifyOutcome> {
        let (arn, ext, tf, ctx) = aws_role(creds)?;
        verify::verify(self, arn, ext, tf, ctx).await
    }

    async fn inventory(&self, creds: &Credentials, _scope: &Scope) -> Result<Vec<Resource>> {
        aws_role(creds)?;
        Err(ConnectorError::Provider(
            "aws inventory: not implemented".into(),
        ))
    }

    async fn cost_daily(&self, creds: &Credentials, _days: u32) -> Result<Vec<CostRow>> {
        aws_role(creds)?;
        Err(ConnectorError::Provider(
            "aws cost_daily: not implemented".into(),
        ))
    }

    async fn metrics(&self, _creds: &Credentials, _q: MetricQuery) -> Result<Vec<MetricPoint>> {
        Err(ConnectorError::Provider(
            "aws metrics: not implemented".into(),
        ))
    }
}
