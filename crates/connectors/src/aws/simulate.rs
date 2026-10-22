//! Restore-role simulation via `iam:SimulatePrincipalPolicy`.
use super::client::provider_err;
use crate::{ConnectorError, Result, SimulationResult};
use aws_sdk_iam::types::{ContextEntry, ContextKeyTypeEnum, PolicyEvaluationDecisionType};

pub const SIMULATE_ACTIONS: &[&str] = &["iam:SimulatePrincipalPolicy"];

/// What a restore needs: start the job, use the KMS key, recreate the database or instance.
pub const RESTORE_ACTIONS: &[&str] = &[
    "backup:StartRestoreJob",
    "kms:CreateGrant",
    "kms:Decrypt",
    "rds:RestoreDBInstanceFromDBSnapshot",
    "ec2:RunInstances",
];

/// Sorted `allowed`, `denied` and `unknown` actions for `role_arn`, simulated from a session in
/// `own_account`. See `Connector::simulate_restore` for the contract.
pub async fn simulate_restore(
    iam: &aws_sdk_iam::Client,
    role_arn: &str,
    own_account: &str,
) -> Result<SimulationResult> {
    let all_unknown = || SimulationResult {
        unknown: RESTORE_ACTIONS.iter().map(|a| a.to_string()).collect(),
        ..Default::default()
    };
    // The session cannot read a role in another account; that is not a finding.
    if role_arn.split(':').nth(4) != Some(own_account) {
        return Ok(all_unknown());
    }
    // Backup's restore grants are for an AWS resource; without this key KMS conditions fail.
    let grant = ContextEntry::builder()
        .context_key_name("kms:GrantIsForAWSResource")
        .context_key_values("true")
        .context_key_type(ContextKeyTypeEnum::Boolean)
        .build();
    let sent = iam
        .simulate_principal_policy()
        .policy_source_arn(role_arn)
        .set_action_names(Some(
            RESTORE_ACTIONS.iter().map(|a| a.to_string()).collect(),
        ))
        .context_entries(grant)
        .send()
        .await;
    // AccessDenied stays an error: it is OpsAgent's own permission gap, a partial result.
    let out = match sent.map_err(provider_err) {
        Ok(out) => out,
        Err(ConnectorError::Api { code: Some(c), .. }) if c == "NoSuchEntity" => {
            return Ok(all_unknown());
        }
        Err(e) => return Err(e),
    };
    let mut r = SimulationResult::default();
    for e in out.evaluation_results() {
        let to = match e.eval_decision() {
            PolicyEvaluationDecisionType::ExplicitDeny => &mut r.denied,
            _ if !e.missing_context_values().is_empty() => &mut r.unknown,
            PolicyEvaluationDecisionType::Allowed => &mut r.allowed,
            _ => &mut r.denied,
        };
        to.push(e.eval_action_name().to_owned());
    }
    for v in [&mut r.allowed, &mut r.denied, &mut r.unknown] {
        v.sort();
    }
    Ok(r)
}
