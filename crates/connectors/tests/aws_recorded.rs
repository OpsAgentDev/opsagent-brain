//! Recorded SDK responses via `aws-smithy-mocks`: modeled output structs replayed through the
//! real client (serialisation, pagination and error metadata included).

use aws_smithy_mocks::{mock, mock_client, RuleMode};
use opsagent_connectors::aws::client::{
    assume, is_access_denied, parse_role_arn, session_name, AwsOutbound,
};
use opsagent_connectors::aws::verify::deployed_actions;
use opsagent_connectors::CallContext;
use uuid::Uuid;

fn ctx() -> CallContext {
    CallContext {
        organisation_id: Uuid::parse_str("0192f0a0-0000-7000-8000-0000aabbccdd").unwrap(),
        run_id: Uuid::parse_str("0192f0a0-0000-7000-8000-000011223344").unwrap(),
        trigger: "manual".into(),
    }
}

#[test]
fn role_arn_and_session_name() {
    let a = parse_role_arn("arn:aws:iam::123456789012:role/opsagent/OpsAgentReadRole-aabbccdd")
        .unwrap();
    assert_eq!(
        (a.partition.as_str(), a.account.as_str(), a.name.as_str()),
        ("aws", "123456789012", "OpsAgentReadRole-aabbccdd")
    );
    assert!(parse_role_arn("arn:aws:iam::123:role/x").is_err());
    assert!(parse_role_arn("arn:aws:s3:::bucket").is_err());
    assert_eq!(session_name(&ctx()), "opsagent-aabbccdd-11223344");
}

#[tokio::test]
async fn assume_sends_session_name_tags_and_external_id() {
    use aws_sdk_sts::operation::assume_role::AssumeRoleOutput;
    use aws_sdk_sts::types::Credentials;
    let ok = mock!(aws_sdk_sts::Client::assume_role)
        .match_requests(|r| {
            let tags: Vec<_> = r.tags().iter().map(|t| (t.key(), t.value())).collect();
            r.role_session_name() == Some("opsagent-aabbccdd-11223344")
                && r.external_id() == Some("ext-1")
                && r.duration_seconds() == Some(3600)
                && r.policy().is_some()
                && tags.contains(&("tenant", "0192f0a0-0000-7000-8000-0000aabbccdd"))
                && tags.contains(&("trigger", "manual"))
                && tags.contains(&("run", "0192f0a0-0000-7000-8000-000011223344"))
        })
        .then_output(|| {
            AssumeRoleOutput::builder()
                .credentials(
                    Credentials::builder()
                        .access_key_id("AKIA")
                        .secret_access_key("secret")
                        .session_token("token")
                        .expiration(aws_smithy_types::DateTime::from_secs(2_000_000_000))
                        .build()
                        .unwrap(),
                )
                .build()
        });
    let sts = mock_client!(aws_sdk_sts, RuleMode::Sequential, [&ok]);
    let base = aws_config::SdkConfig::builder().build();
    let cfg = assume(
        &sts,
        &base,
        &AwsOutbound::default(),
        "arn:aws:iam::123456789012:role/OpsAgentReadRole-aabbccdd",
        Some("ext-1"),
        &ctx(),
        "{}",
    )
    .await
    .unwrap();
    assert!(cfg.credentials_provider().is_some());
    assert_eq!(ok.num_calls(), 1);
}

#[tokio::test]
async fn assume_without_external_id_access_denied_is_detected() {
    use aws_sdk_sts::error::ErrorMetadata;
    use aws_sdk_sts::operation::assume_role::AssumeRoleError;
    let denied = mock!(aws_sdk_sts::Client::assume_role)
        .match_requests(|r| r.external_id().is_none())
        .then_error(|| {
            AssumeRoleError::generic(ErrorMetadata::builder().code("AccessDenied").build())
        });
    let sts = mock_client!(aws_sdk_sts, RuleMode::Sequential, [&denied]);
    let err = assume(
        &sts,
        &aws_config::SdkConfig::builder().build(),
        &AwsOutbound::default(),
        "arn:aws:iam::123456789012:role/OpsAgentReadRole-aabbccdd",
        None,
        &ctx(),
        "{}",
    )
    .await
    .unwrap_err();
    assert!(is_access_denied(&err));
}

#[tokio::test]
async fn deployed_actions_reads_inline_and_attached_policies() {
    use aws_sdk_iam::operation::{
        get_role::GetRoleOutput, get_role_policy::GetRolePolicyOutput,
        list_attached_role_policies::ListAttachedRolePoliciesOutput,
        list_role_policies::ListRolePoliciesOutput,
    };
    use aws_sdk_iam::types::{AttachedPolicy, Role};
    let doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ec2:Describe*","ec2:TerminateInstances"],"Resource":"*"},{"Effect":"Deny","Action":"kms:Decrypt","Resource":"*"}]}"#;
    let encoded = urlencoding::encode(doc).into_owned();
    let get_role = mock!(aws_sdk_iam::Client::get_role).then_output(|| {
        GetRoleOutput::builder()
            .role(
                Role::builder()
                    .path("/")
                    .role_name("R")
                    .role_id("id")
                    .arn("arn:aws:iam::123456789012:role/R")
                    .create_date(aws_smithy_types::DateTime::from_secs(0))
                    .max_session_duration(3600)
                    .build()
                    .unwrap(),
            )
            .build()
    });
    let list = mock!(aws_sdk_iam::Client::list_role_policies).then_output(|| {
        ListRolePoliciesOutput::builder()
            .policy_names("OpsAgentReadAllowlist")
            .is_truncated(false)
            .build()
            .unwrap()
    });
    let get = mock!(aws_sdk_iam::Client::get_role_policy)
        .match_requests(|r| r.policy_name() == Some("OpsAgentReadAllowlist"))
        .then_output(move || {
            GetRolePolicyOutput::builder()
                .role_name("R")
                .policy_name("OpsAgentReadAllowlist")
                .policy_document(encoded.clone())
                .build()
                .unwrap()
        });
    let attached = mock!(aws_sdk_iam::Client::list_attached_role_policies).then_output(|| {
        ListAttachedRolePoliciesOutput::builder()
            .attached_policies(
                AttachedPolicy::builder()
                    .policy_arn("arn:aws:iam::aws:policy/ReadOnlyAccess")
                    .build(),
            )
            .is_truncated(false)
            .build()
    });
    let iam = mock_client!(
        aws_sdk_iam,
        RuleMode::MatchAny,
        [&get_role, &list, &get, &attached]
    );
    let p = deployed_actions(&iam, "R").await.unwrap();
    let allow: Vec<_> = p.allow.values().cloned().collect();
    assert_eq!(
        allow,
        vec![
            "attached-policy:arn:aws:iam::aws:policy/ReadOnlyAccess",
            "ec2:Describe*",
            "ec2:TerminateInstances"
        ]
    );
    assert!(p.deny.contains_key("kms:decrypt"));
}
