use opsagent_connectors::aws::policy_diff::{
    TEMPLATE_V1_ALLOW, TEMPLATE_V1_DENY, TEMPLATE_V1_TERRAFORM_ALLOW,
};
use serde_yaml::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../templates/aws");

fn raw() -> String {
    std::fs::read_to_string(format!("{DIR}/opsagent-read-role-v1.yaml")).unwrap()
}

fn yaml() -> Value {
    serde_yaml::from_str(&raw()).unwrap()
}

fn strs(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) => vec![s.clone()],
        Value::Sequence(xs) => xs.iter().flat_map(strs).collect(),
        _ => vec![],
    }
}

/// Collects (effect, actions) from every statement under `v`; `!If` takes its "true" branch,
/// i.e. the template as deployed with Terraform state parameters set.
fn statements(v: &Value, out: &mut Vec<(String, Vec<String>)>) {
    match v {
        Value::Tagged(t) if t.tag == "!If" => statements(&t.value.as_sequence().unwrap()[1], out),
        Value::Tagged(t) => statements(&t.value, out),
        Value::Sequence(xs) => xs.iter().for_each(|x| statements(x, out)),
        Value::Mapping(m) => {
            if let (Some(e), Some(a)) = (m.get("Effect"), m.get("Action")) {
                out.push((e.as_str().unwrap().to_owned(), strs(a)));
            } else {
                m.values().for_each(|x| statements(x, out));
            }
        }
        _ => {}
    }
}

fn role() -> Value {
    yaml()["Resources"]["OpsAgentReadRole"]["Properties"].clone()
}

#[test]
fn trust_requires_external_id_and_allows_tag_session() {
    let p = role();
    assert_eq!(p["MaxSessionDuration"], Value::from(3600));
    let stmt = &p["AssumeRolePolicyDocument"]["Statement"][0];
    assert_eq!(stmt["Effect"], Value::from("Allow"));
    let actions = strs(&stmt["Action"]);
    assert!(actions.contains(&"sts:AssumeRole".into()));
    assert!(actions.contains(&"sts:TagSession".into()));
    let cond = &stmt["Condition"]["StringEquals"]["sts:ExternalId"];
    let Value::Tagged(t) = cond else {
        panic!("ExternalId condition must be !Ref: {cond:?}")
    };
    assert_eq!(t.tag, "!Ref");
    assert_eq!(t.value, Value::from("ExternalId"));
}

#[test]
fn deny_list_covers_data_plane() {
    let mut st = vec![];
    statements(&role()["Policies"], &mut st);
    let deny: BTreeSet<String> = st
        .iter()
        .filter(|(e, _)| e == "Deny")
        .flat_map(|(_, a)| a.clone())
        .collect();
    for a in [
        "ec2:GetPasswordData",
        "ec2:GetConsoleOutput",
        "ec2:GetConsoleScreenshot",
        "lambda:GetFunction",
        "s3:GetObject*",
        "ssm:GetParameter*",
        "secretsmanager:GetSecretValue",
        "kms:Decrypt",
        "sqs:ReceiveMessage",
        "dynamodb:GetItem",
        "dynamodb:Query",
        "dynamodb:Scan",
        "dynamodb:BatchGetItem",
        "rds:DownloadDBLogFilePortion",
        "logs:GetLogEvents",
    ] {
        assert!(deny.contains(a), "missing deny {a}");
    }
}

#[test]
fn outputs_and_iam_scope() {
    let y = yaml();
    assert!(y["Outputs"]["RoleArn"].is_mapping());
    assert!(y["Outputs"]["TemplateVersion"].is_mapping());
    assert!(
        raw().contains("Resource: !Sub \"arn:aws:iam::${AWS::AccountId}:role/OpsAgentReadRole-*\"")
    );
}

#[test]
fn rust_constants_match_yaml() {
    let mut st = vec![];
    statements(&role()["Policies"], &mut st);
    let set = |eff: &str| -> BTreeSet<String> {
        st.iter()
            .filter(|(e, _)| e == eff)
            .flat_map(|(_, a)| a.clone())
            .collect()
    };
    let mut allow: BTreeSet<String> = TEMPLATE_V1_ALLOW.iter().map(|s| s.to_string()).collect();
    allow.insert(TEMPLATE_V1_TERRAFORM_ALLOW.into());
    let deny: BTreeSet<String> = TEMPLATE_V1_DENY.iter().map(|s| s.to_string()).collect();
    assert_eq!(set("Allow"), allow);
    assert_eq!(set("Deny"), deny);
}

#[test]
fn sha256_file_matches_template() {
    let want = std::fs::read_to_string(format!("{DIR}/opsagent-read-role-v1.sha256")).unwrap();
    let got: String = Sha256::digest(raw().as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(want.split_whitespace().next().unwrap(), got);
}
