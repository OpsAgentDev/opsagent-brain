use opsagent_connectors::aws::policy_diff::{
    render_template, substitute, RenderedRole, TemplateParams, TEMPLATE_V1_YAML, TEMPLATE_V2_YAML,
    TEMPLATE_VERSION,
};
use opsagent_connectors::ConnectorError;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../templates/aws");

/// Every version stays in the repo and in the bucket; the last is the current one.
const VERSIONS: [(&str, &str); 2] = [("1", TEMPLATE_V1_YAML), ("2", TEMPLATE_V2_YAML)];

fn file(version: &str, ext: &str) -> String {
    std::fs::read_to_string(format!("{DIR}/opsagent-read-role-v{version}.{ext}")).unwrap()
}

/// The current template's file.
fn raw() -> String {
    file(TEMPLATE_VERSION, "yaml")
}

/// The current template, rendered.
fn render_current(p: &TemplateParams) -> opsagent_connectors::Result<RenderedRole> {
    render_template(TEMPLATE_VERSION, p)
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
fn embedded_templates_are_the_files_and_the_last_is_current() {
    for (version, embedded) in VERSIONS {
        assert_eq!(embedded, file(version, "yaml"), "v{version}");
        let y: serde_norway::Value = serde_norway::from_str(embedded).unwrap();
        let p = &y["Parameters"]["TemplateVersion"];
        assert_eq!(p["Default"].as_str(), Some(version));
        assert_eq!(p["AllowedValues"][0].as_str(), Some(version));
    }
    assert_eq!(VERSIONS[VERSIONS.len() - 1].0, TEMPLATE_VERSION);
    assert!(matches!(
        render_template("3", &params(None)),
        Err(ConnectorError::Template(_))
    ));
}

/// The quick-create link and verify work unchanged across versions.
#[test]
fn versions_share_parameters_outputs_trust_and_denies() {
    let part = |yaml: &str, key: &str| {
        let mut y: serde_norway::Value = serde_norway::from_str(yaml).unwrap();
        if let Some(v) = y["Parameters"]["TemplateVersion"].as_mapping_mut() {
            v.clear();
        }
        y[key].clone()
    };
    let rendered = |v: &str| {
        let r = render_template(v, &params(Some(("tf-state", "envs/prod/")))).unwrap();
        let deny: Vec<Value> = stmts(&r.policies)
            .into_iter()
            .filter(|s| s["Effect"] == "Deny" || s["Sid"] == "ReadOwnRolePolicy")
            .collect();
        (r.trust, deny)
    };
    for key in ["Parameters", "Conditions", "Outputs"] {
        assert_eq!(part(TEMPLATE_V1_YAML, key), part(TEMPLATE_V2_YAML, key));
    }
    assert_eq!(rendered("1"), rendered("2"));
}

#[test]
fn trust_requires_external_id_and_allows_tag_session() {
    let y: serde_norway::Value = serde_norway::from_str(&raw()).unwrap();
    assert_eq!(
        y["Resources"]["OpsAgentReadRole"]["Properties"]["MaxSessionDuration"],
        serde_norway::Value::from(3600)
    );
    let t = render_current(&params(None)).unwrap().trust;
    assert_eq!(
        t["Statement"],
        json!([
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999999999999:role/opsagent-outbound"},
                "Action": ["sts:AssumeRole"],
                "Condition": {"StringEquals": {"sts:ExternalId": "ext-1"}}
            },
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999999999999:role/opsagent-outbound"},
                "Action": ["sts:TagSession"]
            }
        ])
    );
}

#[test]
fn deny_list_covers_data_plane() {
    for (version, _) in VERSIONS {
        deny_list_covers_data_plane_in(version);
    }
}

fn deny_list_covers_data_plane_in(version: &str) {
    let s = stmts(&render_template(version, &params(None)).unwrap().policies);
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
    let r = render_current(&params(None)).unwrap();
    assert_eq!(r.policies.len(), 2, "no OpsAgentTerraformState policy");
    let s = stmts(&r.policies);
    let d = by_sid(&s, "DenyObjectReads").unwrap();
    assert_eq!(d["Resource"], "*");
    assert!(d.get("NotResource").is_none());
    assert!(by_sid(&s, "ReadTerraformState").is_none());
}

#[test]
fn with_terraform_params_prefix_is_carved_out_and_allowed() {
    let r = render_current(&params(Some(("tf-state", "envs/prod/")))).unwrap();
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
    let y: serde_norway::Value = serde_norway::from_str(&raw()).unwrap();
    let p = &y["Parameters"];
    assert_eq!(
        p["TerraformStateBucket"]["AllowedPattern"].as_str(),
        Some("^$|^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
    );
    assert_eq!(
        p["TerraformStatePrefix"]["AllowedPattern"].as_str(),
        Some("^$|^[^*$]*/$")
    );
}

#[test]
fn outputs_and_iam_scope() {
    let y: serde_norway::Value = serde_norway::from_str(&raw()).unwrap();
    assert!(y["Outputs"]["RoleArn"].is_mapping());
    assert!(y["Outputs"]["TemplateVersion"].is_mapping());
    let s = stmts(&render_current(&params(None)).unwrap().policies);
    assert_eq!(
        by_sid(&s, "ReadOwnRolePolicy").unwrap()["Resource"],
        "arn:aws:iam::123456789012:role/OpsAgentReadRole-*"
    );
}

#[test]
fn sha256_files_match_templates() {
    for (version, embedded) in VERSIONS {
        let want = file(version, "sha256");
        let got: String = Sha256::digest(embedded.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let name = format!("opsagent-read-role-v{version}.yaml");
        assert_eq!(want.split_whitespace().collect::<Vec<_>>(), [&got, &name]);
    }
}

#[test]
fn unclosed_placeholder_is_an_error_not_a_panic() {
    let p = params(Some(("tf-state", "a${/")));
    assert!(matches!(
        substitute("x/${Unclosed", &p),
        Err(ConnectorError::Template(_))
    ));
    // Substituted values are never re-scanned, so a `${` inside one is harmless here...
    assert_eq!(
        substitute("arn:${TerraformStatePrefix}*", &p).unwrap(),
        "arn:a${/*"
    );
    // ...and rendering rejects the prefix before substitution.
    assert!(matches!(
        render_current(&p),
        Err(ConnectorError::Template(_))
    ));
}

#[test]
fn substituted_values_are_inserted_literally_once() {
    let p = params(Some(("tf-state", "x${ExternalId}/")));
    assert_eq!(
        substitute(
            "arn:aws:s3:::${TerraformStateBucket}/${TerraformStatePrefix}*",
            &p
        )
        .unwrap(),
        "arn:aws:s3:::tf-state/x${ExternalId}/*"
    );
}

#[test]
fn invalid_terraform_bucket_or_prefix_is_rejected() {
    for (bucket, prefix) in [
        ("Tf-State", "envs/"),
        ("tf_state", "envs/"),
        ("-tf", "envs/"),
        ("tf-state-", "envs/"),
        ("ab", "envs/"),
        ("tf-state", "envs"),
        ("tf-state", "envs/*/"),
        ("tf-state", "x${ExternalId}/"),
        ("tf-state", ""),
        ("", "envs/"),
    ] {
        let r = render_current(&params(Some((bucket, prefix))));
        assert!(
            matches!(r, Err(ConnectorError::Template(_))),
            "{bucket:?} {prefix:?} accepted"
        );
    }
    assert!(render_current(&params(Some(("tf.state-01", "envs/prod/")))).is_ok());
}

/// IAM action patterns: `*` matches any run of characters; names are case-insensitive.
fn action_matches(pattern: &str, action: &str) -> bool {
    let (p, a) = (pattern.to_ascii_lowercase(), action.to_ascii_lowercase());
    match p.split_once('*') {
        None => p == a,
        Some((head, tail)) => {
            a.len() >= head.len() + tail.len() && a.starts_with(head) && a.ends_with(tail)
        }
    }
}

fn actions(s: &[Value], effect: &str) -> BTreeSet<String> {
    s.iter()
        .filter(|x| x["Effect"] == effect)
        .flat_map(|x| x["Action"].as_array().unwrap().clone())
        .map(|a| a.as_str().unwrap().to_owned())
        .collect()
}

/// The current template allows exactly the calls the connector can make: one missing breaks a
/// scan, one more is a grant nobody uses. A new SDK call is added to its session list
/// (`aws::session_actions`) and to the template.
#[test]
fn current_template_allows_exactly_the_connector_calls() {
    let s = stmts(&render_current(&params(None)).unwrap().policies);
    let (allow, deny) = (actions(&s, "Allow"), actions(&s, "Deny"));
    let used: BTreeSet<String> = opsagent_connectors::aws::session_actions()
        .map(str::to_owned)
        .collect();
    assert_eq!(allow, used);
    assert!(!allow.iter().any(|a| a.contains('*')), "{allow:?}");
    for a in &used {
        assert!(!deny.iter().any(|p| action_matches(p, a)), "{a} denied");
    }
}

/// Version 1 is wider, so the connections made with it keep every call.
#[test]
fn version_1_still_allows_every_connector_call() {
    let s = stmts(&render_template("1", &params(None)).unwrap().policies);
    let (allow, deny) = (actions(&s, "Allow"), actions(&s, "Deny"));
    assert!(action_matches("backup:List*", "backup:ListBackupJobs"));
    assert!(!action_matches("s3:GetObject*", "s3:ListAllMyBuckets"));
    for a in opsagent_connectors::aws::session_actions() {
        assert!(
            allow.iter().any(|p| action_matches(p, a)),
            "{a} not allowed"
        );
        assert!(!deny.iter().any(|p| action_matches(p, a)), "{a} denied");
    }
}

/// What the second promise review found in version 1 (MVP live list 11.1, 11.2).
#[test]
fn current_template_drops_the_unused_services() {
    let s = stmts(&render_current(&params(None)).unwrap().policies);
    let allow = actions(&s, "Allow");
    for gone in [
        "ecs:",
        "eks:",
        "lambda:",
        "autoscaling:",
        "config:",
        "securityhub:",
        "budgets:",
        "health:",
        "kms:",
        "logs:FilterLogEvents",
        "logs:DescribeLogStreams",
        "cloudtrail:LookupEvents",
        "ec2:DescribeVpnConnections",
        "ec2:DescribeSpot",
        "sagemaker:Describe",
    ] {
        assert!(!allow.iter().any(|a| a.starts_with(gone)), "{gone} allowed");
    }
}
