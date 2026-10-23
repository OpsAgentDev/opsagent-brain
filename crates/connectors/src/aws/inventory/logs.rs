//! CloudWatch Logs groups: retention and stored bytes (for the no-retention cost estimate).
use super::Target;
use crate::aws::client::provider_err;
use crate::Result;
use opsagent_core::resource::{Resource, ResourceKind};
use serde_json::json;
use std::collections::BTreeMap;

pub async fn log_groups(
    logs: &aws_sdk_cloudwatchlogs::Client,
    t: &Target<'_>,
) -> Result<Vec<Resource>> {
    let mut out = vec![];
    let mut pages = logs.describe_log_groups().into_paginator().send();
    while let Some(page) = pages.next().await {
        for g in page.map_err(provider_err)?.log_groups() {
            let name = g.log_group_name().unwrap_or_default();
            // `arn` carries a trailing `:*`; `log_group_arn` does not.
            let arn = g
                .log_group_arn()
                .map(str::to_owned)
                .or_else(|| g.arn().map(|a| a.trim_end_matches(":*").to_owned()))
                .unwrap_or_else(|| t.arn("logs", &format!("log-group:{name}")));
            let attrs = json!({
                "service": "logs",
                "retention_days": g.retention_in_days(),
                "stored_bytes": g.stored_bytes().unwrap_or(0).max(0),
            });
            out.push(t.resource(ResourceKind::Log, arn, name, BTreeMap::new(), attrs));
        }
    }
    Ok(out)
}
