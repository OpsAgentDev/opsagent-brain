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

/// Sorted allowed and denied actions for `role_arn`; implicit and explicit denies both count.
/// See `Connector::simulate_restore` for when the result is `unknown`.
pub async fn simulate_restore(
    iam: &aws_sdk_iam::Client,
    role_arn: &str,
) -> Result<SimulationResult> {
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
    let unknown = || SimulationResult {
        unknown: true,
        ..Default::default()
    };
    let out = match sent.map_err(provider_err) {
        Ok(out) => out,
        Err(ConnectorError::Api { code: Some(c), .. })
            if matches!(
                c.as_str(),
                "NoSuchEntity" | "AccessDenied" | "AccessDeniedException"
            ) =>
        {
            return Ok(unknown());
        }
        Err(e) => return Err(e),
    };
    let mut r = SimulationResult::default();
    for e in out.evaluation_results() {
        if !e.missing_context_values().is_empty() {
            r.unknown = true;
        }
        let to = if e.eval_decision() == &PolicyEvaluationDecisionType::Allowed {
            &mut r.allowed
        } else {
            &mut r.denied
        };
        to.push(e.eval_action_name().to_owned());
    }
    if r.unknown {
        r.denied.clear();
    }
    r.allowed.sort();
    r.denied.sort();
    Ok(r)
}
