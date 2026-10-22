use super::client::{assume, is_access_denied, parse_role_arn, provider_err, session_policy};
use super::policy_diff::{policy_diff, template_v1_actions, PolicyActions};
use super::AwsConnector;
use crate::{CallContext, ConnectorError, Result, VerifyOutcome};

const VERIFY_ACTIONS: &[&str] = &[
    "sts:GetCallerIdentity",
    "iam:GetRole",
    "iam:ListRolePolicies",
    "iam:GetRolePolicy",
    "iam:ListAttachedRolePolicies",
];

/// Reads the deployed role's inline and attached policies. Attached managed policies are not
/// part of the template, so each one surfaces as an extra `attached-policy:<arn>` grant.
pub async fn deployed_actions(iam: &aws_sdk_iam::Client, role_name: &str) -> Result<PolicyActions> {
    let mut p = PolicyActions::default();
    let role = iam
        .get_role()
        .role_name(role_name)
        .send()
        .await
        .map_err(provider_err)?;
    if role
        .role
        .and_then(|r| r.max_session_duration)
        .unwrap_or(3600)
        > 3600
    {
        p.add(true, "role:MaxSessionDuration>3600");
    }
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
        // GetRolePolicy returns the document URL-encoded.
        let doc = urlencoding::decode(&doc).map_err(|e| ConnectorError::Provider(e.to_string()))?;
        let doc =
            serde_json::from_str(&doc).map_err(|e| ConnectorError::Provider(e.to_string()))?;
        p.add_document(&doc);
    }
    let mut attached = iam
        .list_attached_role_policies()
        .role_name(role_name)
        .into_paginator()
        .items()
        .send();
    while let Some(a) = attached.next().await {
        let a = a.map_err(provider_err)?;
        p.add(
            true,
            &format!("attached-policy:{}", a.policy_arn.unwrap_or_default()),
        );
    }
    Ok(p)
}

pub(crate) async fn verify(
    c: &AwsConnector,
    role_arn: &str,
    external_id: &str,
    terraform_state: bool,
    ctx: &CallContext,
) -> Result<VerifyOutcome> {
    let arn = parse_role_arn(role_arn)?;
    let base = c.base().await;
    let policy = session_policy(VERIFY_ACTIONS);
    let sts = aws_sdk_sts::Client::new(base);
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
    let deployed = deployed_actions(&aws_sdk_iam::Client::new(&session), &arn.name).await?;
    let (extra_grants, missing_grants) =
        policy_diff(&deployed, &template_v1_actions(terraform_state));
    Ok(VerifyOutcome {
        assume_with_ok: true,
        assume_without_denied,
        account_matches: ident.account.as_deref() == Some(arn.account.as_str()),
        extra_grants,
        missing_grants,
    })
}
