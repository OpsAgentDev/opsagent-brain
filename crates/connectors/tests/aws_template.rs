use opsagent_connectors::aws::policy_diff::{render_template_v1, TemplateParams, TEMPLATE_V1_YAML};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../templates/aws");

fn raw() -> String {
    std::fs::read_to_string(format!("{DIR}/opsagent-read-role-v1.yaml")).unwrap()
}

fn params(tf: Option<(&'static str, &'static str)>) -> TemplateParams<'static> {
    TemplateParams {
        partition: "aws",
        account: "123456789012",
        external_id: "ext-1",
        principal: "arn:aws:iam::999999999999:role/opsagent-outbound",
        terraform: tf,
    }
}

fn stmts(docs: &[Value]) -> Vec<Value> {
    docs.iter()
        .flat_map(|d| d["Statement"].as_array().unwrap().clone())
        .collect()
}

fn by_sid<'a>(s: &'a [Value], sid: &str) -> Option<&'a Value> {
    s.iter().find(|x| x["Sid"] == sid)
}

#[test]
fn embedded_template_is_the_file() {
    assert_eq!(TEMPLATE_V1_YAML, raw());
}

#[test]
fn trust_requires_external_id_and_allows_tag_session() {
    let y: serde_yaml::Value = serde_yaml::from_str(&raw()).unwrap();
    assert_eq!(
        y["Resources"]["OpsAgentReadRole"]["Properties"]["MaxSessionDuration"],
        serde_yaml::Value::from(3600)
    );
    let t = render_template_v1(&params(None)).trust;
    assert_eq!(
        t["Statement"][0],
        json!({
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::999999999999:role/opsagent-outbound"},
            "Action": ["sts:AssumeRole", "sts:TagSession"],
            "Condition": {"StringEquals": {"sts:ExternalId": "ext-1"}}
        })
    );
}

#[test]
fn deny_list_covers_data_plane() {
    let s = stmts(&render_template_v1(&params(None)).policies);
    let deny: BTreeSet<String> = s
        .iter()
        .filter(|x| x["Effect"] == "Deny")
        .flat_map(|x| x["Action"].as_array().unwrap().clone())
        .map(|a| a.as_str().unwrap().to_owned())
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
        "ec2:GetLaunchTemplateData",
        "ec2:DescribeLaunchTemplateVersions",
        "ec2:DescribeInstanceAttribute",
        "autoscaling:DescribeLaunchConfigurations",
        "lambda:GetLayerVersion",
        "lambda:GetLayerVersionByArn",
        "ecs:DescribeTasks",
        "sagemaker:DescribeModel",
        "sagemaker:DescribeEndpointConfig",
        "sagemaker:DescribeTrainingJob",
        "sagemaker:DescribeProcessingJob",
        "sagemaker:DescribeTransformJob",
    ] {
        assert!(deny.contains(a), "missing deny {a}");
    }
    // Spec trade-off: these stay allowed; the connector strips env from responses.
    for a in [
        "ecs:DescribeTaskDefinition",
        "lambda:GetFunctionConfiguration",
    ] {
        assert!(!deny.contains(a), "{a} must not be denied");
    }
}

#[test]
fn without_terraform_params_object_reads_are_denied_everywhere() {
    let r = render_template_v1(&params(None));
    assert_eq!(r.policies.len(), 2, "no OpsAgentTerraformState policy");
    let s = stmts(&r.policies);
    let d = by_sid(&s, "DenyObjectReads").unwrap();
    assert_eq!(d["Resource"], "*");
    assert!(d.get("NotResource").is_none());
    assert!(by_sid(&s, "ReadTerraformState").is_none());
}

#[test]
fn with_terraform_params_prefix_is_carved_out_and_allowed() {
    let r = render_template_v1(&params(Some(("tf-state", "envs/prod/"))));
    assert_eq!(r.policies.len(), 3);
    let s = stmts(&r.policies);
    let arn = "arn:aws:s3:::tf-state/envs/prod/*";
    let d = by_sid(&s, "DenyObjectReads").unwrap();
    assert_eq!(d["NotResource"], arn);
    assert!(d.get("Resource").is_none());
    let a = by_sid(&s, "ReadTerraformState").unwrap();
    assert_eq!(a["Action"], json!(["s3:GetObject"]));
    assert_eq!(a["Resource"], arn);
    let tpl =
        "!Sub \"arn:${AWS::Partition}:s3:::${TerraformStateBucket}/${TerraformStatePrefix}*\"";
    assert_eq!(raw().matches(tpl).count(), 2);
}

#[test]
fn terraform_parameters_are_constrained() {
    let y: serde_yaml::Value = serde_yaml::from_str(&raw()).unwrap();
    let p = &y["Parameters"];
    assert_eq!(
        p["TerraformStateBucket"]["AllowedPattern"].as_str(),
        Some("^$|^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
    );
    assert_eq!(
        p["TerraformStatePrefix"]["AllowedPattern"].as_str(),
        Some("^$|^[^*]*/$")
    );
}

#[test]
fn outputs_and_iam_scope() {
    let y: serde_yaml::Value = serde_yaml::from_str(&raw()).unwrap();
    assert!(y["Outputs"]["RoleArn"].is_mapping());
    assert!(y["Outputs"]["TemplateVersion"].is_mapping());
    let s = stmts(&render_template_v1(&params(None)).policies);
    assert_eq!(
        by_sid(&s, "ReadOwnRolePolicy").unwrap()["Resource"],
        "arn:aws:iam::123456789012:role/OpsAgentReadRole-*"
    );
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
