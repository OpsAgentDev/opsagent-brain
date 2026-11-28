//! IAM roles and their trust policies, for check 14.
use super::Target;
use crate::aws::client::provider_err;
use crate::aws::verify::decode_doc;
use crate::Result;
use opsagent_core::resource::{Resource, ResourceKind};
use serde_json::json;
use std::collections::BTreeMap;

/// Every role of the account except service-linked ones and OpsAgent's own read role, whose
/// trust policy holds the connection's ExternalId and must never be stored or shown.
pub async fn iam_roles(iam: &aws_sdk_iam::Client, t: &Target<'_>) -> Result<Vec<Resource>> {
    let mut out = vec![];
    let mut roles = iam.list_roles().into_paginator().items().send();
    while let Some(role) = roles.next().await {
        let role = role.map_err(provider_err)?;
        if role.path().starts_with("/aws-service-role/")
            || role.role_name().starts_with("OpsAgentReadRole-")
        {
            continue;
        }
        let trust_policy = decode_doc(role.assume_role_policy_document().unwrap_or("{}"))?;
        out.push(t.resource(
            ResourceKind::Identity,
            role.arn().to_owned(),
            role.role_name(),
            BTreeMap::new(),
            json!({"service": "iam_role", "path": role.path(), "trust_policy": trust_policy}),
        ));
    }
    Ok(out)
}
