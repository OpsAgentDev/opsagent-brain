//! Restore-role simulation via `iam:SimulatePrincipalPolicy`.
use super::client::provider_err;
use crate::{Result, SimulationResult};
use aws_sdk_iam::types::PolicyEvaluationDecisionType;

pub(crate) const SIMULATE_ACTIONS: &[&str] = &["iam:SimulatePrincipalPolicy"];

/// What a restore needs: start the job, use the KMS key, recreate the database or instance.
pub const RESTORE_ACTIONS: &[&str] = &[
    "backup:StartRestoreJob",
    "kms:CreateGrant",
    "kms:Decrypt",
    "rds:RestoreDBInstanceFromDBSnapshot",
    "ec2:RunInstances",
];

/// Sorted allowed and denied actions for `role_arn`; implicit and explicit denies both count.
pub async fn simulate_restore(
    iam: &aws_sdk_iam::Client,
    role_arn: &str,
) -> Result<SimulationResult> {
    let out = iam
        .simulate_principal_policy()
        .policy_source_arn(role_arn)
        .set_action_names(Some(
            RESTORE_ACTIONS.iter().map(|a| a.to_string()).collect(),
        ))
        .send()
        .await
        .map_err(provider_err)?;
    let mut r = SimulationResult::default();
    for e in out.evaluation_results() {
        let to = if e.eval_decision() == &PolicyEvaluationDecisionType::Allowed {
            &mut r.allowed
        } else {
            &mut r.denied
        };
        to.push(e.eval_action_name().to_owned());
    }
    r.allowed.sort();
    r.denied.sort();
    Ok(r)
}
