use opsagent_connectors::aws::policy_diff::{policy_diff, template_v1_actions, PolicyActions};
use serde_json::json;

#[test]
fn identical_policy_has_no_diff() {
    let t = template_v1_actions(false);
    assert_eq!(policy_diff(&t, &t), (vec![], vec![]));
}

#[test]
fn added_action_is_extra() {
    let mut deployed = template_v1_actions(false);
    deployed.add(true, "ec2:TerminateInstances");
    let (extra, missing) = policy_diff(&deployed, &template_v1_actions(false));
    assert_eq!(extra, vec!["ec2:TerminateInstances"]);
    assert!(missing.is_empty());
}

#[test]
fn removed_action_is_missing() {
    let mut deployed = template_v1_actions(false);
    deployed.allow.remove("iam:listusers");
    let (extra, missing) = policy_diff(&deployed, &template_v1_actions(false));
    assert!(extra.is_empty());
    assert_eq!(missing, vec!["iam:ListUsers"]);
}

#[test]
fn terraform_param_makes_scoped_get_object_expected() {
    let deployed = template_v1_actions(true);
    assert_eq!(
        policy_diff(&deployed, &template_v1_actions(true)),
        (vec![], vec![])
    );
    // Without the parameters the same grant is a superset.
    let (extra, _) = policy_diff(&deployed, &template_v1_actions(false));
    assert_eq!(extra, vec!["s3:GetObject"]);
}

#[test]
fn dropped_deny_is_extra() {
    let mut deployed = template_v1_actions(false);
    deployed.deny.remove("kms:decrypt");
    let (extra, _) = policy_diff(&deployed, &template_v1_actions(false));
    assert_eq!(extra, vec!["deny-missing:kms:Decrypt"]);
}

#[test]
fn parses_policy_documents_case_insensitively() {
    let mut p = PolicyActions::default();
    p.add_document(&json!({"Statement": {"Effect": "Allow", "Action": "EC2:describe*"}}));
    p.add_document(&json!({"Statement": [
        {"Effect": "Deny", "Action": ["kms:Decrypt"]},
        {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}
    ]}));
    let mut expected = PolicyActions::default();
    expected.add(true, "ec2:Describe*");
    expected.add(false, "kms:Decrypt");
    let (extra, missing) = policy_diff(&p, &expected);
    assert_eq!(extra, vec!["notaction:iam:*"]);
    assert!(missing.is_empty());
}
