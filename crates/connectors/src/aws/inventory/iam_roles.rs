//! IAM roles and their trust policies, for check 14.
use super::Target;
use crate::aws::client::provider_err;
use crate::aws::verify::decode_doc;
use crate::Result;
use opsagent_core::resource::{Resource, ResourceKind};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

/// Every role of the account, none skipped by its name or path: anyone who can create a role
/// could name one to hide it. A trust policy that cannot be decoded is stored as null, so one
/// bad document does not fail the read; check 14 skips such a role.
pub async fn iam_roles(iam: &aws_sdk_iam::Client, t: &Target<'_>) -> Result<Vec<Resource>> {
    let mut out = vec![];
    let mut roles = iam.list_roles().into_paginator().items().send();
    while let Some(role) = roles.next().await {
        let role = role.map_err(provider_err)?;
        let trust_policy = match decode_doc(role.assume_role_policy_document().unwrap_or("{}")) {
            Ok(doc) => minimal_trust(&doc),
            Err(_) => {
                tracing::warn!("iam_roles: a trust policy could not be decoded, stored as null");
                Value::Null
            }
        };
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

const KEPT: [&str; 5] = ["Effect", "Action", "NotAction", "Principal", "Condition"];

/// Only what check 14 reads: per statement the effect, action, principal and condition, with
/// every fixed `sts:ExternalId` value replaced. OpsAgent's own role holds the connection's
/// ExternalId in its trust policy, and it must never be stored (a role named to look like it is
/// no reason to trust the name, so every role is treated the same).
fn minimal_trust(doc: &Value) -> Value {
    let statements = match &doc["Statement"] {
        Value::Array(xs) => xs.clone(),
        Value::Null => vec![],
        one => vec![one.clone()],
    };
    let kept: Vec<Value> = statements
        .iter()
        .filter_map(Value::as_object)
        .map(|st| {
            let mut out: Map<String, Value> = st
                .iter()
                .filter(|(k, _)| KEPT.contains(&k.as_str()))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            if let Some(cond) = out.get_mut("Condition") {
                redact_external_ids(cond);
            }
            Value::Object(out)
        })
        .collect();
    json!({ "Statement": kept })
}

/// `{operator: {key: value}}`: every value of an `sts:ExternalId` key (any operator, any key
/// case) that is a non-empty literal becomes `[redacted]`. An empty value or one with `*` or
/// `?` carries no secret and stays, because the check needs to see it.
fn redact_external_ids(cond: &mut Value) {
    let ops = cond
        .as_object_mut()
        .into_iter()
        .flat_map(|o| o.values_mut());
    for keys in ops {
        let keys = keys.as_object_mut().into_iter().flat_map(|o| o.iter_mut());
        for (_, v) in keys.filter(|(k, _)| k.eq_ignore_ascii_case("sts:externalid")) {
            match v {
                Value::Array(xs) => xs.iter_mut().for_each(redact_value),
                other => redact_value(other),
            }
        }
    }
}

fn redact_value(v: &mut Value) {
    let secret = match v {
        Value::String(s) => !s.is_empty() && !s.contains(['*', '?']),
        Value::Number(_) => true,
        _ => false,
    };
    if secret {
        *v = Value::String("[redacted]".into());
    }
}
