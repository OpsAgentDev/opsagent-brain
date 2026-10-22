//! Outbound identity and per-customer sessions. Every customer call goes through `assume`.

use crate::{CallContext, ConnectorError, Result};
use aws_config::{retry::RetryConfig, BehaviorVersion, Region, SdkConfig};
use aws_sdk_sts::config::{Credentials, SharedCredentialsProvider};
use aws_sdk_sts::error::{DisplayErrorContext, ProvideErrorMetadata};
use aws_sdk_sts::types::Tag;
use std::collections::BTreeMap;
use uuid::Uuid;

/// Binary Labs outbound role. `credentials: None` uses the default provider chain.
#[derive(Debug, Clone, Default)]
pub struct AwsOutbound {
    pub credentials: Option<SharedCredentialsProvider>,
    /// ARN customer trust policies must name. `None`: derived from `GetCallerIdentity`.
    pub principal_arn: Option<String>,
    /// Added to every AssumeRole on top of `tenant`, `trigger`, `run`.
    pub session_tags: BTreeMap<String, String>,
}

/// Parsed `arn:<partition>:iam::<account>:role/<path/><name>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleArn {
    pub partition: String,
    pub account: String,
    pub name: String,
}

pub fn parse_role_arn(arn: &str) -> Result<RoleArn> {
    let bad = || ConnectorError::InvalidCredentials("not an IAM role ARN".into());
    let parts: Vec<&str> = arn.splitn(6, ':').collect();
    let [_, partition, "iam", "", account, res] = parts[..] else {
        return Err(bad());
    };
    let name = res.strip_prefix("role/").and_then(|r| r.rsplit('/').next());
    match name {
        Some(n)
            if !n.is_empty()
                && account.len() == 12
                && account.bytes().all(|b| b.is_ascii_digit()) =>
        {
            Ok(RoleArn {
                partition: partition.to_owned(),
                account: account.to_owned(),
                name: n.to_owned(),
            })
        }
        _ => Err(bad()),
    }
}

/// Last 8 hex chars: the random tail of a UUIDv7 (the head is a timestamp and collides).
pub fn short_id(id: &Uuid) -> String {
    let s = id.simple().to_string();
    s[s.len() - 8..].to_owned()
}

pub fn session_name(ctx: &CallContext) -> String {
    format!(
        "opsagent-{}-{}",
        short_id(&ctx.organisation_id),
        short_id(&ctx.run_id)
    )
}

/// SDK error to `ConnectorError::Api`, keeping the AWS error code.
pub(crate) fn provider_err(e: impl std::error::Error + ProvideErrorMetadata) -> ConnectorError {
    ConnectorError::Api {
        code: e.code().map(str::to_owned),
        message: DisplayErrorContext(e).to_string(),
    }
}

/// The provider answered AccessDenied.
fn provider_build_err(e: aws_sdk_sts::error::BuildError) -> ConnectorError {
    ConnectorError::Provider(e.to_string())
}

pub fn is_access_denied(e: &ConnectorError) -> bool {
    matches!(e, ConnectorError::Api { code: Some(c), .. } if matches!(c.as_str(), "AccessDenied" | "AccessDeniedException"))
}

pub(crate) async fn load_base(outbound: &AwsOutbound) -> SdkConfig {
    let mut loader = aws_config::defaults(BehaviorVersion::latest())
        .retry_config(RetryConfig::standard().with_max_attempts(5));
    if let Some(c) = &outbound.credentials {
        loader = loader.credentials_provider(c.clone());
    }
    let cfg = loader.load().await;
    if cfg.region().is_some() {
        cfg
    } else {
        cfg.to_builder()
            .region(Region::from_static("us-east-1"))
            .build()
    }
}

/// AssumeRole into the customer role with session name, tags and a session policy narrowing
/// the job. Returns an `SdkConfig` carrying the temporary credentials; see `is_access_denied`.
pub async fn assume(
    sts: &aws_sdk_sts::Client,
    base: &SdkConfig,
    outbound: &AwsOutbound,
    role_arn: &str,
    external_id: Option<&str>,
    ctx: &CallContext,
    session_policy: &str,
) -> Result<SdkConfig> {
    let mut tags: BTreeMap<String, String> = outbound.session_tags.clone();
    tags.insert("tenant".into(), ctx.organisation_id.to_string());
    tags.insert("trigger".into(), ctx.trigger.clone());
    tags.insert("run".into(), ctx.run_id.to_string());
    let tags = tags
        .into_iter()
        .map(|(k, v)| {
            Tag::builder()
                .key(k)
                .value(v)
                .build()
                .map_err(provider_build_err)
        })
        .collect::<Result<Vec<_>>>()?;
    let out = sts
        .assume_role()
        .role_arn(role_arn)
        .role_session_name(session_name(ctx))
        .set_external_id(external_id.map(str::to_owned))
        .set_tags(Some(tags))
        .policy(session_policy)
        .duration_seconds(3600)
        .send()
        .await
        .map_err(provider_err)?;
    let c = out
        .credentials
        .ok_or_else(|| ConnectorError::Provider("AssumeRole returned no credentials".into()))?;
    let creds = Credentials::new(
        c.access_key_id,
        c.secret_access_key,
        Some(c.session_token),
        std::time::SystemTime::try_from(c.expiration).ok(),
        "opsagent-assume-role",
    );
    Ok(base
        .to_builder()
        .credentials_provider(SharedCredentialsProvider::new(creds))
        .build())
}

/// Session policy: Allow `actions` on `*`. Intersects with the role's own policy.
pub fn session_policy(actions: &[&str]) -> String {
    serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}]
    })
    .to_string()
}
