use super::client::{assume, is_access_denied, parse_role_arn, provider_err, session_policy};
use super::policy_diff::{diff_role, DeployedRole, TemplateParams};
use super::AwsConnector;
use crate::{CallContext, ConnectorError, Result, TerraformState, VerifyOutcome};
use serde_json::Value;

const VERIFY_ACTIONS: &[&str] = &[
    "sts:GetCallerIdentity",
    "iam:GetRole",
    "iam:ListRolePolicies",
    "iam:GetRolePolicy",
    "iam:ListAttachedRolePolicies",
];

/// IAM returns policy documents URL-encoded.
fn decode_doc(doc: &str) -> Result<Value> {
    let doc = urlencoding::decode(doc).map_err(|e| ConnectorError::Provider(e.to_string()))?;
    serde_json::from_str(&doc).map_err(|e| ConnectorError::Provider(e.to_string()))
}

/// Reads trust policy, session duration, inline and attached policies of the deployed role.
pub async fn deployed_role(iam: &aws_sdk_iam::Client, role_name: &str) -> Result<DeployedRole> {
    let role = iam
        .get_role()
        .role_name(role_name)
        .send()
        .await
        .map_err(provider_err)?
        .role
        .ok_or_else(|| ConnectorError::Provider("GetRole returned no role".into()))?;
    let mut out = DeployedRole {
        trust: decode_doc(role.assume_role_policy_document().unwrap_or("{}"))?,
        max_session_duration: role.max_session_duration().unwrap_or(3600),
        ..Default::default()
    };
    let mut names = iam
        .list_role_policies()
        .role_name(role_name)
        .into_paginator()
        .items()
        .send();
    while let Some(name) = names.next().await {
        let name = name.map_err(provider_err)?;
        let doc = iam
            .get_role_policy()
            .role_name(role_name)
            .policy_name(&name)
            .send()
            .await
            .map_err(provider_err)?
            .policy_document;
        out.policies.push(decode_doc(&doc)?);
    }
    let mut attached = iam
        .list_attached_role_policies()
        .role_name(role_name)
        .into_paginator()
        .items()
        .send();
    while let Some(a) = attached.next().await {
        let a = a.map_err(provider_err)?;
        out.attached_policy_arns
            .push(a.policy_arn.unwrap_or_default());
    }
    Ok(out)
}

/// `arn:aws:sts::<acct>:assumed-role/<name>/<session>` -> `arn:aws:iam::<acct>:role/<name>`.
/// shortcut: drops any role path; set `AwsOutbound::principal_arn` when the role has one.
pub fn principal_from_caller(arn: &str) -> String {
    let parts: Vec<&str> = arn.splitn(6, ':').collect();
    match parts[..] {
        [_, partition, "sts", "", account, res] if res.starts_with("assumed-role/") => {
            let name = res.split('/').nth(1).unwrap_or_default();
            format!("arn:{partition}:iam::{account}:role/{name}")
        }
        _ => arn.to_owned(),
    }
}

pub(crate) async fn verify(
    c: &AwsConnector,
    role_arn: &str,
    external_id: &str,
    terraform_state: Option<&TerraformState>,
    ctx: &CallContext,
) -> Result<VerifyOutcome> {
    let arn = parse_role_arn(role_arn)?;
    let base = c.base().await;
    let policy = session_policy(VERIFY_ACTIONS);
    let sts = aws_sdk_sts::Client::new(base);
    let principal = match &c.outbound.principal_arn {
        Some(p) => p.clone(),
        None => {
            let me = sts
                .get_caller_identity()
                .send()
                .await
                .map_err(provider_err)?;
            principal_from_caller(me.arn().unwrap_or_default())
        }
    };
    let with = assume(
        &sts,
        base,
        &c.outbound,
        role_arn,
        Some(external_id),
        ctx,
        &policy,
    )
    .await;
    let without = assume(&sts, base, &c.outbound, role_arn, None, ctx, &policy).await;
    let assume_without_denied = match without {
        Ok(_) => false,
        Err(e) if is_access_denied(&e) => true,
        Err(e) => return Err(provider_err(e)),
    };
    let session = match with {
        Ok(s) => s,
        Err(e) if is_access_denied(&e) => {
            return Ok(VerifyOutcome {
                assume_with_ok: false,
                assume_without_denied,
                account_matches: false,
                extra_grants: vec![],
                missing_grants: vec![],
            })
        }
        Err(e) => return Err(provider_err(e)),
    };
    let ident = aws_sdk_sts::Client::new(&session)
        .get_caller_identity()
        .send()
        .await
        .map_err(provider_err)?;
    let deployed = deployed_role(&aws_sdk_iam::Client::new(&session), &arn.name).await?;
    let params = TemplateParams {
        partition: &arn.partition,
        account: &arn.account,
        external_id,
        principal: &principal,
        terraform: terraform_state.map(|t| (t.bucket.as_str(), t.prefix.as_str())),
    };
    let (extra_grants, missing_grants) = diff_role(&deployed, &params)?;
    Ok(VerifyOutcome {
        assume_with_ok: true,
        assume_without_denied,
        account_matches: ident.account.as_deref() == Some(arn.account.as_str()),
        extra_grants,
        missing_grants,
    })
}
