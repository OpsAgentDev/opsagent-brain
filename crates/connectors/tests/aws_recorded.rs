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

mod inventory {
    use aws_sdk_ec2::operation::{
        describe_instances::DescribeInstancesOutput, describe_volumes::DescribeVolumesOutput,
    };
    use aws_sdk_ec2::types::{
        Instance, InstanceState, InstanceStateName, InstanceType, Reservation, Tag, Volume,
        VolumeAttachment,
    };
    use aws_smithy_mocks::{mock, mock_client, RuleMode};
    use opsagent_connectors::aws::inventory::{ec2_instances, ec2_volumes, strip_env, Target};
    use opsagent_core::resource::{Provider, ResourceKind};
    use serde_json::json;

    const T: Target = Target {
        partition: "aws",
        account: "123456789012",
        region: "eu-west-1",
    };

    #[tokio::test]
    async fn describe_instances_maps_to_compute_resources() {
        let rule = mock!(aws_sdk_ec2::Client::describe_instances).then_output(|| {
            DescribeInstancesOutput::builder()
                .reservations(
                    Reservation::builder()
                        .instances(
                            Instance::builder()
                                .instance_id("i-0aaa")
                                .instance_type(InstanceType::M5Large)
                                .state(
                                    InstanceState::builder()
                                        .name(InstanceStateName::Running)
                                        .build(),
                                )
                                .tags(Tag::builder().key("Name").value("web-1").build())
                                .build(),
                        )
                        .instances(
                            Instance::builder()
                                .instance_id("i-0bbb")
                                .instance_type(InstanceType::P32xlarge)
                                .state(
                                    InstanceState::builder()
                                        .name(InstanceStateName::Stopped)
                                        .build(),
                                )
                                .build(),
                        )
                        .build(),
                )
                .build()
        });
        let ec2 = mock_client!(aws_sdk_ec2, RuleMode::Sequential, [&rule]);
        let r = ec2_instances(&ec2, &T).await.unwrap();
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|r| r.kind == ResourceKind::Compute
            && r.provider == Provider::Aws
            && r.account == "123456789012"
            && r.region == "eu-west-1"));
        assert_eq!(
            r[0].identity,
            "arn:aws:ec2:eu-west-1:123456789012:instance/i-0aaa"
        );
        assert_eq!(r[0].name, "web-1");
        assert_eq!(r[0].tags["Name"], "web-1");
        assert_eq!(
            r[0].attributes,
            json!({"service": "ec2", "state": "running", "instance_type": "m5.large",
                   "accelerated": false, "cpu_avg_7d": null, "monthly_cost_usd": null})
        );
        assert_eq!(r[1].name, "i-0bbb");
        assert_eq!(r[1].attributes["accelerated"], true);
        assert_eq!(r[1].attributes["state"], "stopped");
    }

    #[tokio::test]
    async fn describe_volumes_maps_to_storage_resources() {
        let rule = mock!(aws_sdk_ec2::Client::describe_volumes).then_output(|| {
            DescribeVolumesOutput::builder()
                .volumes(
                    Volume::builder()
                        .volume_id("vol-1")
                        .size(100)
                        .attachments(VolumeAttachment::builder().instance_id("i-0aaa").build())
                        .build(),
                )
                .volumes(Volume::builder().volume_id("vol-2").size(8).build())
                .build()
        });
        let ec2 = mock_client!(aws_sdk_ec2, RuleMode::Sequential, [&rule]);
        let r = ec2_volumes(&ec2, &T).await.unwrap();
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|r| r.kind == ResourceKind::Storage));
        assert_eq!(
            r[0].identity,
            "arn:aws:ec2:eu-west-1:123456789012:volume/vol-1"
        );
        assert_eq!(
            r[0].attributes,
            json!({"service": "ebs", "attached": true, "size_gb": 100, "monthly_cost_usd": null})
        );
        assert_eq!(r[1].attributes["attached"], false);
    }

    #[test]
    fn strip_env_removes_environment_and_secrets_everywhere() {
        let mut v = json!({
            "taskDefinition": {
                "family": "api",
                "containerDefinitions": [{
                    "name": "api",
                    "image": "api:1",
                    "environment": [{"name": "DB_PASSWORD", "value": "hunter2"}],
                    "secrets": [{"name": "TOKEN", "valueFrom": "arn:aws:ssm:..."}]
                }]
            },
            "Environment": {"Variables": {"KEY": "v"}}
        });
        strip_env(&mut v);
        let s = v.to_string();
        assert!(!s.contains("hunter2") && !s.contains("TOKEN") && !s.contains("KEY"));
        assert!(v.get("Environment").is_none());
        let c = &v["taskDefinition"]["containerDefinitions"][0];
        assert!(c.get("environment").is_none() && c.get("secrets").is_none());
        assert_eq!(c["image"], "api:1");
    }

    #[tokio::test]
    async fn security_groups_compute_world_ports_and_attachment() {
        use aws_sdk_ec2::operation::{
            describe_network_interfaces::DescribeNetworkInterfacesOutput,
            describe_security_groups::DescribeSecurityGroupsOutput,
        };
        use aws_sdk_ec2::types::{
            GroupIdentifier, IpPermission, IpRange, Ipv6Range, NetworkInterface,
            NetworkInterfaceAttachment, SecurityGroup,
        };
        let enis = mock!(aws_sdk_ec2::Client::describe_network_interfaces).then_output(|| {
            let g = |id: &str| GroupIdentifier::builder().group_id(id).build();
            DescribeNetworkInterfacesOutput::builder()
                .network_interfaces(
                    NetworkInterface::builder()
                        .description("Primary network interface")
                        .attachment(
                            NetworkInterfaceAttachment::builder()
                                .instance_id("i-1")
                                .build(),
                        )
                        .groups(g("sg-ssh"))
                        .build(),
                )
                .network_interfaces(
                    NetworkInterface::builder()
                        .description("ELB app/web/123")
                        .groups(g("sg-web"))
                        .build(),
                )
                .build()
        });
        let world = |from: i32, to: i32| {
            IpPermission::builder()
                .ip_protocol("tcp")
                .from_port(from)
                .to_port(to)
                .ip_ranges(IpRange::builder().cidr_ip("0.0.0.0/0").build())
                .build()
        };
        let sgs = mock!(aws_sdk_ec2::Client::describe_security_groups).then_output(move || {
            let sg = |id: &str, p: Vec<IpPermission>| {
                SecurityGroup::builder()
                    .group_id(id)
                    .group_name(id)
                    .set_ip_permissions(Some(p))
                    .build()
            };
            DescribeSecurityGroupsOutput::builder()
                .security_groups(sg("sg-ssh", vec![world(22, 22)]))
                .security_groups(sg(
                    "sg-web",
                    vec![
                        IpPermission::builder()
                            .ip_protocol("tcp")
                            .from_port(443)
                            .to_port(443)
                            .ipv6_ranges(Ipv6Range::builder().cidr_ipv6("::/0").build())
                            .build(),
                        IpPermission::builder()
                            .ip_protocol("tcp")
                            .from_port(80)
                            .to_port(80)
                            .ip_ranges(IpRange::builder().cidr_ip("10.0.0.0/8").build())
                            .build(),
                    ],
                ))
                .security_groups(sg("sg-db", vec![world(3000, 3400)]))
                .build()
        });
        let ec2 = mock_client!(aws_sdk_ec2, RuleMode::MatchAny, [&enis, &sgs]);
        let r = opsagent_connectors::aws::inventory::security_groups(&ec2, &T)
            .await
            .unwrap();
        let a: Vec<_> = r.iter().map(|r| r.attributes.clone()).collect();
        assert_eq!(
            a[0],
            json!({"service": "sg", "open_world_ports": [22], "attached_to": "instance"})
        );
        assert_eq!(
            a[1],
            json!({"service": "sg", "open_world_ports": [443], "attached_to": "lb"})
        );
        assert_eq!(
            a[2],
            json!({"service": "sg", "open_world_ports": [3000, 3306, 3389, 3400], "attached_to": "none"})
        );
        assert_eq!(
            r[0].identity,
            "arn:aws:ec2:eu-west-1:123456789012:security-group/sg-ssh"
        );
    }

    #[test]
    fn credential_report_maps_users() {
        use chrono::TimeZone;
        let csv = "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated
<root_account>,arn:aws:iam::123456789012:root,2020-01-01T00:00:00+00:00,not_supported,N/A,not_supported,not_supported,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A
stale,arn:aws:iam::123456789012:user/stale,2020-01-01T00:00:00+00:00,true,N/A,N/A,N/A,false,true,2026-06-24T00:00:00+00:00,2026-07-14T00:00:00+00:00,us-east-1,s3,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A
admin,arn:aws:iam::123456789012:user/admin,2020-01-01T00:00:00+00:00,true,N/A,N/A,N/A,true,true,2026-10-12T00:00:00+00:00,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A
bot,arn:aws:iam::123456789012:user/bot,2020-01-01T00:00:00+00:00,false,N/A,N/A,N/A,false,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A
";
        let now = chrono::Utc
            .with_ymd_and_hms(2026, 10, 22, 12, 0, 0)
            .unwrap();
        let g = Target {
            region: "global",
            ..T
        };
        let r = opsagent_connectors::aws::inventory::credential_report_users(
            csv,
            &|u| u == "admin",
            &g,
            now,
        );
        assert_eq!(r.len(), 3);
        assert_eq!(r[0].identity, "arn:aws:iam::123456789012:user/stale");
        assert_eq!(r[0].kind, ResourceKind::Identity);
        assert_eq!(
            r[0].attributes,
            json!({"service": "iam", "key_age_days": 120, "key_last_used_days": 100,
                   "mfa": false, "console": true, "admin": false})
        );
        assert_eq!(r[1].attributes["key_last_used_days"], 10);
        assert_eq!(r[1].attributes["admin"], true);
        assert_eq!(r[2].attributes["key_age_days"], serde_json::Value::Null);
    }
}
