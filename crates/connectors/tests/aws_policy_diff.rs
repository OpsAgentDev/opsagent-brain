use opsagent_connectors::aws::policy_diff::{
    diff_role, policy_diff, render_template_v1, trust_diff, DeployedRole, PolicyStatements,
    TemplateParams,
};
use serde_json::{json, Value};

fn params(tf: Option<(&'static str, &'static str)>) -> TemplateParams<'static> {
    TemplateParams {
        partition: "aws",
        account: "123456789012",
        external_id: "ext-1",
        principal: "arn:aws:iam::999999999999:role/opsagent-outbound",
        terraform: tf,
    }
}

fn template(tf: Option<(&'static str, &'static str)>) -> Vec<Value> {
    render_template_v1(&params(tf)).unwrap().policies
}

fn diff(
    deployed: &[Value],
    tf: Option<(&'static str, &'static str)>,
) -> (Vec<String>, Vec<String>) {
    policy_diff(
        &PolicyStatements::from_documents(deployed),
        &PolicyStatements::from_documents(&template(tf)),
    )
}

/// Mutable statement by Sid across the rendered docs.
fn stmt<'a>(docs: &'a mut [Value], sid: &str) -> &'a mut Value {
    docs.iter_mut()
        .flat_map(|d| d["Statement"].as_array_mut().unwrap().iter_mut())
        .find(|s| s["Sid"] == sid)
        .unwrap()
}

#[test]
fn identical_policy_has_no_diff() {
    assert_eq!(diff(&template(None), None), (vec![], vec![]));
}

#[test]
fn shape_differences_do_not_count() {
    // IAM may hand back a single action as a string and statements reordered.
    let mut docs = template(None);
    stmt(&mut docs, "ReadOptInLogEvents")["Action"] = json!("logs:FilterLogEvents");
    docs.reverse();
    assert_eq!(diff(&docs, None), (vec![], vec![]));
}

#[test]
fn added_action_is_extra() {
    let mut docs = template(None);
    stmt(&mut docs, "ReadMetadata")["Action"]
        .as_array_mut()
        .unwrap()
        .push(json!("ec2:TerminateInstances"));
    assert_eq!(
        diff(&docs, None),
        (vec!["ec2:TerminateInstances".into()], vec![])
    );
}

#[test]
fn removed_action_is_missing() {
    let mut docs = template(None);
    stmt(&mut docs, "ReadMetadata")["Action"]
        .as_array_mut()
        .unwrap()
        .retain(|a| a != "iam:ListUsers");
    assert_eq!(diff(&docs, None), (vec![], vec!["iam:ListUsers".into()]));
}

#[test]
fn widened_resource_scope_is_extra() {
    let mut docs = template(None);
    stmt(&mut docs, "ReadOwnRolePolicy")["Resource"] = json!("*");
    let (extra, missing) = diff(&docs, None);
    assert!(extra.contains(&"iam:GetRolePolicy".to_owned()), "{extra:?}");
    assert!(
        missing.contains(&"iam:GetRolePolicy".to_owned()),
        "{missing:?}"
    );
}

#[test]
fn terraform_param_makes_scoped_get_object_expected() {
    let tf = Some(("tf-state", "envs/prod/"));
    assert_eq!(diff(&template(tf), tf), (vec![], vec![]));
    // The same deployment checked against a stack launched without the parameters.
    let (extra, _) = diff(&template(tf), None);
    assert!(extra.contains(&"s3:GetObject on arn:aws:s3:::tf-state/envs/prod/*".to_owned()));
    assert!(extra.contains(&"deny-missing:s3:GetObject*".to_owned()));
}

#[test]
fn dropped_deny_is_extra() {
    let mut docs = template(None);
    stmt(&mut docs, "DenyDataPlane")["Action"]
        .as_array_mut()
        .unwrap()
        .retain(|a| a != "kms:Decrypt");
    assert_eq!(diff(&docs, None).0, vec!["deny-missing:kms:Decrypt"]);
}

#[test]
fn deny_with_never_matching_condition_is_extra() {
    let mut docs = template(None);
    stmt(&mut docs, "DenyDataPlane")["Condition"] =
        json!({"StringEquals": {"aws:PrincipalTag/never": "set"}});
    let (extra, missing) = diff(&docs, None);
    assert!(
        extra.contains(&"deny-missing:kms:Decrypt".to_owned()),
        "{extra:?}"
    );
    assert!(extra.contains(&"deny-missing:sagemaker:DescribeModel".to_owned()));
    assert!(missing.is_empty());
}

#[test]
fn not_action_allow_is_extra() {
    let mut docs = template(None);
    docs.push(json!({"Statement": {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}}));
    assert_eq!(diff(&docs, None).0, vec!["notaction:iam:* on *"]);
}

fn trust() -> Value {
    render_template_v1(&params(None)).unwrap().trust
}

#[test]
fn identical_trust_has_no_diff() {
    assert!(trust_diff(&trust(), &trust()).is_empty());
}

#[test]
fn trust_with_extra_principal_is_reported() {
    let mut t = trust();
    t["Statement"][0]["Principal"]["AWS"] = json!([
        "arn:aws:iam::999999999999:role/opsagent-outbound",
        "arn:aws:iam::111111111111:root"
    ]);
    assert_eq!(
        trust_diff(&t, &trust()),
        vec!["trust-policy:Principal differs"]
    );
}

#[test]
fn trust_without_external_id_is_reported_without_leaking_it() {
    let mut t = trust();
    t["Statement"][0]
        .as_object_mut()
        .unwrap()
        .remove("Condition");
    let d = trust_diff(&t, &trust());
    assert_eq!(d, vec!["trust-policy:Condition differs"]);
    assert!(!d.concat().contains("ext-1"));
}

#[test]
fn diff_role_combines_policies_trust_attached_and_duration() {
    let deployed = DeployedRole {
        trust: trust(),
        max_session_duration: 43200,
        policies: template(None),
        attached_policy_arns: vec!["arn:aws:iam::aws:policy/ReadOnlyAccess".into()],
    };
    assert_eq!(
        diff_role(&deployed, &params(None)).unwrap(),
        (
            vec![
                "attached-policy:arn:aws:iam::aws:policy/ReadOnlyAccess".to_owned(),
                "role:MaxSessionDuration>3600".to_owned()
            ],
            vec![]
        )
    );
}
