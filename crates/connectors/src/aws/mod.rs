//! AWS connector. Spec: docs/tech-spec/aws-connection.md.

pub mod client;
pub mod cost;
pub mod inventory;
pub mod metrics;
pub mod policy_diff;
pub mod simulate;
pub mod verify;

pub use client::AwsOutbound;

use crate::{
    CallContext, Capability, Connector, ConnectorError, CostRow, Credentials, InventoryResult,
    MetricPoint, MetricQuery, Result, Scope, SimulationResult, TerraformState, VerifyOutcome,
};
use async_trait::async_trait;
use aws_config::SdkConfig;
use opsagent_core::resource::Provider;
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

    /// Customer session narrowed to `actions`.
    async fn session(
        &self,
        role_arn: &str,
        external_id: &str,
        ctx: &CallContext,
        actions: &[&str],
    ) -> Result<SdkConfig> {
        let base = self.base().await;
        let sts = aws_sdk_sts::Client::new(base);
        let policy = client::session_policy(actions);
        client::assume(
            &sts,
            base,
            &self.outbound,
            role_arn,
            Some(external_id),
            ctx,
            &policy,
        )
        .await
    }

    /// Outbound config, loaded on first use so `registry` can stay synchronous.
    async fn base(&self) -> &SdkConfig {
        self.base
            .get_or_init(|| client::load_base(&self.outbound))
            .await
    }
}

type AwsRole<'a> = (
    &'a str,
    &'a str,
    Option<&'a TerraformState>,
    &'a CallContext,
);

fn aws_role(creds: &Credentials) -> Result<AwsRole<'_>> {
    match creds {
        Credentials::AwsRole {
            role_arn,
            external_id,
            terraform_state,
            context,
        } => Ok((role_arn, external_id, terraform_state.as_ref(), context)),
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
            Metrics,
            IamReport,
            PublicAccess,
            Backups,
            Certificates,
            Logging,
            Gpu,
        ]
        .into()
    }

    async fn verify(&self, creds: &Credentials) -> Result<VerifyOutcome> {
        let (arn, ext, tf, ctx) = aws_role(creds)?;
        verify::verify(self, arn, ext, tf, ctx).await
    }

    async fn inventory(&self, creds: &Credentials, scope: &Scope) -> Result<InventoryResult> {
        let (arn, ext, _, ctx) = aws_role(creds)?;
        let role = client::parse_role_arn(arn)?;
        let session = self
            .session(arn, ext, ctx, inventory::INVENTORY_ACTIONS)
            .await?;
        inventory::inventory(&session, &role.partition, &role.account, scope).await
    }

    async fn cost_daily(&self, creds: &Credentials, days: u32) -> Result<Vec<CostRow>> {
        let (arn, ext, _, ctx) = aws_role(creds)?;
        let session = self.session(arn, ext, ctx, cost::COST_ACTIONS).await?;
        // Cost Explorer is served from us-east-1 only.
        let session = session
            .to_builder()
            .region(aws_config::Region::from_static("us-east-1"))
            .build();
        let ce = aws_sdk_costexplorer::Client::new(&session);
        cost::cost_daily(&ce, days, chrono::Utc::now().date_naive()).await
    }

    /// `q.resource_identity` is an EC2 instance ARN; the call runs in the ARN's region.
    async fn metrics(&self, creds: &Credentials, q: MetricQuery) -> Result<Vec<MetricPoint>> {
        let (arn, ext, _, ctx) = aws_role(creds)?;
        let (region, id) = metrics::instance_from_arn(&q.resource_identity)?;
        let session = self.session(arn, ext, ctx, metrics::METRIC_ACTIONS).await?;
        let session = session
            .to_builder()
            .region(aws_config::Region::new(region.to_owned()))
            .build();
        let cw = aws_sdk_cloudwatch::Client::new(&session);
        metrics::metric_points(&cw, id, &q.metric, q.hours, chrono::Utc::now()).await
    }

    async fn simulate_restore(
        &self,
        creds: &Credentials,
        role_arn: &str,
    ) -> Result<SimulationResult> {
        let (arn, ext, _, ctx) = aws_role(creds)?;
        let own = client::parse_role_arn(arn)?.account;
        let session = self
            .session(arn, ext, ctx, simulate::SIMULATE_ACTIONS)
            .await?;
        let iam = aws_sdk_iam::Client::new(&session);
        simulate::simulate_restore(&iam, role_arn, &own).await
    }
}
