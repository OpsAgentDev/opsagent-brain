//! Expected action sets of `templates/aws/opsagent-read-role-v1.yaml` and the diff that
//! `verify` runs against the deployed role. `tests/aws_template.rs` keeps the constants in sync.

use serde_json::Value;
use std::collections::BTreeMap;

pub const TEMPLATE_V1_ALLOW: &[&str] = &[
    "ec2:Describe*",
    "ec2:List*",
    "ec2:Get*",
    "ecs:Describe*",
    "ecs:List*",
    "ecs:Get*",
    "eks:Describe*",
    "eks:List*",
    "eks:Get*",
    "lambda:Describe*",
    "lambda:List*",
    "lambda:Get*",
    "rds:Describe*",
    "rds:List*",
    "rds:Get*",
    "elasticloadbalancing:Describe*",
    "elasticloadbalancing:List*",
    "elasticloadbalancing:Get*",
    "autoscaling:Describe*",
    "autoscaling:List*",
    "autoscaling:Get*",
    "cloudwatch:Describe*",
    "cloudwatch:List*",
    "cloudwatch:Get*",
    "config:Describe*",
    "config:List*",
    "config:Get*",
    "securityhub:Describe*",
    "securityhub:List*",
    "securityhub:Get*",
    "guardduty:Describe*",
    "guardduty:List*",
    "guardduty:Get*",
    "acm:Describe*",
    "acm:List*",
    "acm:Get*",
    "backup:Describe*",
    "backup:List*",
    "backup:Get*",
    "budgets:Describe*",
    "budgets:List*",
    "budgets:Get*",
    "health:Describe*",
    "health:List*",
    "health:Get*",
    "logs:DescribeLogGroups",
    "logs:DescribeLogStreams",
    "logs:FilterLogEvents",
    "cloudtrail:LookupEvents",
    "cloudtrail:DescribeTrails",
    "cloudtrail:GetTrailStatus",
    "iam:GetAccountSummary",
    "iam:ListUsers",
    "iam:ListAccessKeys",
    "iam:GetAccessKeyLastUsed",
    "iam:ListMFADevices",
    "iam:GetCredentialReport",
    "iam:GenerateCredentialReport",
    "iam:ListAttachedUserPolicies",
    "iam:ListRoles",
    "iam:SimulatePrincipalPolicy",
    "iam:GetRole",
    "iam:GetRolePolicy",
    "iam:ListRolePolicies",
    "iam:ListAttachedRolePolicies",
    "s3:ListAllMyBuckets",
    "s3:GetBucketPolicyStatus",
    "s3:GetBucketPublicAccessBlock",
    "s3:GetAccountPublicAccessBlock",
    "s3:GetBucketLocation",
    "s3:GetBucketTagging",
    "ce:GetCostAndUsage",
    "ce:GetAnomalies",
    "sagemaker:List*",
    "sagemaker:Describe*",
    "kms:ListKeys",
    "kms:DescribeKey",
    "sts:GetCallerIdentity",
];

/// Granted only when both `TerraformStateBucket` and `TerraformStatePrefix` are set.
pub const TEMPLATE_V1_TERRAFORM_ALLOW: &str = "s3:GetObject";

pub const TEMPLATE_V1_DENY: &[&str] = &[
    "s3:GetObject*",
    "ssm:GetParameter*",
    "secretsmanager:GetSecretValue",
    "kms:Decrypt",
    "sqs:ReceiveMessage",
    "dynamodb:GetItem",
    "dynamodb:Query",
    "dynamodb:Scan",
    "dynamodb:BatchGetItem",
    "lambda:GetFunction",
    "ec2:GetPasswordData",
    "ec2:GetConsoleOutput",
    "ec2:GetConsoleScreenshot",
    "logs:GetLogEvents",
    "rds:DownloadDBLogFilePortion",
];

/// Normalised action sets. Keys are lowercase (IAM actions are case-insensitive), values keep
/// the original spelling for reporting.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyActions {
    pub allow: BTreeMap<String, String>,
    pub deny: BTreeMap<String, String>,
}

impl PolicyActions {
    pub fn add(&mut self, allow: bool, action: &str) {
        let a = action.trim();
        let set = if allow {
            &mut self.allow
        } else {
            &mut self.deny
        };
        set.insert(a.to_lowercase(), a.to_owned());
    }

    /// Adds every statement of a JSON policy document (`Statement` object or array,
    /// `Action` string or array). `NotAction` allows are recorded as `notaction:<action>`
    /// so they always surface as extra.
    pub fn add_document(&mut self, doc: &Value) {
        let stmts = match &doc["Statement"] {
            Value::Array(xs) => xs.iter().collect(),
            v @ Value::Object(_) => vec![v],
            _ => vec![],
        };
        for s in stmts {
            let allow = s["Effect"].as_str() == Some("Allow");
            for a in as_strs(&s["Action"]) {
                self.add(allow, a);
            }
            for a in as_strs(&s["NotAction"]) {
                self.add(allow, &format!("notaction:{a}"));
            }
        }
    }
}

fn as_strs(v: &Value) -> Vec<&str> {
    match v {
        Value::String(s) => vec![s],
        Value::Array(xs) => xs.iter().filter_map(Value::as_str).collect(),
        _ => vec![],
    }
}

/// Expected action sets for template v1 with its parameters.
pub fn template_v1_actions(terraform_state: bool) -> PolicyActions {
    let mut p = PolicyActions::default();
    TEMPLATE_V1_ALLOW.iter().for_each(|a| p.add(true, a));
    TEMPLATE_V1_DENY.iter().for_each(|a| p.add(false, a));
    if terraform_state {
        p.add(true, TEMPLATE_V1_TERRAFORM_ALLOW);
    }
    p
}

/// `(extra, missing)`. Extra: allows not in the template, plus template denies absent from the
/// deployed role (reported as `deny-missing:<action>`, since a dropped deny widens access).
/// Missing: template allows not deployed. Both sorted.
pub fn policy_diff(
    deployed: &PolicyActions,
    expected: &PolicyActions,
) -> (Vec<String>, Vec<String>) {
    let minus = |a: &BTreeMap<String, String>, b: &BTreeMap<String, String>| {
        a.iter()
            .filter(|(k, _)| !b.contains_key(*k))
            .map(|(_, v)| v.clone())
            .collect::<Vec<_>>()
    };
    let mut extra = minus(&deployed.allow, &expected.allow);
    extra.extend(
        minus(&expected.deny, &deployed.deny)
            .into_iter()
            .map(|a| format!("deny-missing:{a}")),
    );
    (extra, minus(&expected.allow, &deployed.allow))
}
