//! Recorded SDK responses for the attributes checks 11 to 13 read.

use aws_smithy_mocks::{mock, mock_client, RuleMode};
use chrono::TimeZone;
use opsagent_connectors::aws::inventory::{
    credential_report_users, ec2_instances, ec2_snapshots, ec2_volumes, rds_clusters,
    rds_instances, Target,
};
use serde_json::json;

const T: Target = Target {
    partition: "aws",
    account: "123456789012",
    region: "eu-west-1",
};

#[tokio::test]
async fn describe_instances_maps_metadata_options_and_public_ip() {
    use aws_sdk_ec2::operation::describe_instances::DescribeInstancesOutput;
    use aws_sdk_ec2::types::{
        HttpTokensState, Instance, InstanceMetadataEndpointState, InstanceMetadataOptionsResponse,
        Reservation,
    };
    let v1 = Instance::builder()
        .instance_id("i-v1")
        .public_ip_address("203.0.113.9")
        .metadata_options(
            InstanceMetadataOptionsResponse::builder()
                .http_tokens(HttpTokensState::Optional)
                .http_endpoint(InstanceMetadataEndpointState::Enabled)
                .build(),
        )
        .build();
    let v2 = Instance::builder()
        .instance_id("i-v2")
        .metadata_options(
            InstanceMetadataOptionsResponse::builder()
                .http_tokens(HttpTokensState::Required)
                .http_endpoint(InstanceMetadataEndpointState::Disabled)
                .build(),
        )
        .build();
    let rule = mock!(aws_sdk_ec2::Client::describe_instances).then_output(move || {
        DescribeInstancesOutput::builder()
            .reservations(
                Reservation::builder()
                    .instances(v1.clone())
                    .instances(v2.clone())
                    .build(),
            )
            .build()
    });
    let ec2 = mock_client!(aws_sdk_ec2, RuleMode::Sequential, [&rule]);
    let r = ec2_instances(&ec2, &T).await.unwrap();
    let pick = |i: usize| {
        let a = &r[i].attributes;
        (
            a["metadata_http_tokens"].clone(),
            a["metadata_http_endpoint"].clone(),
            a["has_public_ip"].clone(),
        )
    };
    assert_eq!(pick(0), (json!("optional"), json!("enabled"), json!(true)));
    assert_eq!(
        pick(1),
        (json!("required"), json!("disabled"), json!(false))
    );
}

#[tokio::test]
async fn describe_volumes_maps_encrypted_flag() {
    use aws_sdk_ec2::operation::describe_volumes::DescribeVolumesOutput;
    use aws_sdk_ec2::types::Volume;
    let rule = mock!(aws_sdk_ec2::Client::describe_volumes).then_output(|| {
        DescribeVolumesOutput::builder()
            .volumes(Volume::builder().volume_id("a").encrypted(true).build())
            .volumes(Volume::builder().volume_id("b").encrypted(false).build())
            .build()
    });
    let ec2 = mock_client!(aws_sdk_ec2, RuleMode::Sequential, [&rule]);
    let r = ec2_volumes(&ec2, &T).await.unwrap();
    assert_eq!(r[0].attributes["encrypted"], true);
    assert_eq!(r[1].attributes["encrypted"], false);
}

#[tokio::test]
async fn describe_snapshots_maps_encrypted_owner_self() {
    use aws_sdk_ec2::operation::describe_snapshots::DescribeSnapshotsOutput;
    use aws_sdk_ec2::types::Snapshot;
    let rule = mock!(aws_sdk_ec2::Client::describe_snapshots)
        .match_requests(|r| r.owner_ids() == ["self"])
        .then_output(|| {
            DescribeSnapshotsOutput::builder()
                .snapshots(
                    Snapshot::builder()
                        .snapshot_id("snap-1")
                        .encrypted(false)
                        .build(),
                )
                .snapshots(Snapshot::builder().snapshot_id("snap-2").build())
                .build()
        });
    let ec2 = mock_client!(aws_sdk_ec2, RuleMode::Sequential, [&rule]);
    let r = ec2_snapshots(&ec2, &T).await.unwrap();
    assert_eq!(
        r[0].identity,
        "arn:aws:ec2:eu-west-1:123456789012:snapshot/snap-1"
    );
    assert_eq!(
        r[0].attributes,
        json!({"service": "ebs_snapshot", "encrypted": false})
    );
    assert_eq!(r[1].attributes["encrypted"], serde_json::Value::Null);
}

#[tokio::test]
async fn describe_db_clusters_maps_storage_encrypted() {
    use aws_sdk_rds::operation::describe_db_clusters::DescribeDbClustersOutput;
    use aws_sdk_rds::types::DbCluster;
    let rule = mock!(aws_sdk_rds::Client::describe_db_clusters).then_output(|| {
        DescribeDbClustersOutput::builder()
            .db_clusters(
                DbCluster::builder()
                    .db_cluster_identifier("aurora-1")
                    .db_cluster_arn("arn:aws:rds:eu-west-1:123456789012:cluster:aurora-1")
                    .storage_encrypted(false)
                    .build(),
            )
            .build()
    });
    let rds = mock_client!(aws_sdk_rds, RuleMode::Sequential, [&rule]);
    let r = rds_clusters(&rds, &T).await.unwrap();
    assert_eq!(r[0].name, "aurora-1");
    assert_eq!(
        r[0].attributes,
        json!({"service": "rds_cluster", "encrypted": false})
    );
}

#[tokio::test]
async fn rds_member_of_cluster_reports_no_encryption() {
    use aws_sdk_rds::operation::describe_db_instances::DescribeDbInstancesOutput;
    use aws_sdk_rds::types::DbInstance;
    let rule = mock!(aws_sdk_rds::Client::describe_db_instances).then_output(|| {
        DescribeDbInstancesOutput::builder()
            .db_instances(
                DbInstance::builder()
                    .db_instance_identifier("solo")
                    .storage_encrypted(false)
                    .build(),
            )
            .db_instances(
                DbInstance::builder()
                    .db_instance_identifier("member")
                    .db_cluster_identifier("aurora-1")
                    .storage_encrypted(false)
                    .build(),
            )
            .build()
    });
    let rds = mock_client!(aws_sdk_rds, RuleMode::Sequential, [&rule]);
    let r = rds_instances(&rds, &T).await.unwrap();
    assert_eq!(r[0].attributes["encrypted"], false);
    assert_eq!(r[1].attributes["encrypted"], serde_json::Value::Null);
}

#[test]
fn credential_report_maps_never_used_key_and_password_age() {
    let csv = r#"user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated
fresh,arn:aws:iam::123456789012:user/fresh,2020-01-01T00:00:00+00:00,true,2026-10-20T00:00:00+00:00,2026-01-01T00:00:00+00:00,N/A,true,true,2026-09-22T00:00:00+00:00,N/A,N/A,N/A,true,2026-10-01T00:00:00+00:00,2026-10-02T00:00:00+00:00,us-east-1,s3,false,N/A,false,N/A
dormant,arn:aws:iam::123456789012:user/dormant,2020-01-01T00:00:00+00:00,true,N/A,2026-01-02T00:00:00+00:00,N/A,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A
"#;
    let now = chrono::Utc
        .with_ymd_and_hms(2026, 10, 22, 12, 0, 0)
        .unwrap();
    let g = Target {
        region: "global",
        ..T
    };
    let r = credential_report_users(csv, &|_| false, &g, now);
    let a = |i: usize| &r[i].attributes;
    assert_eq!(a(0)["access_keys_active"], 2);
    assert_eq!(a(0)["unused_key_age_days"], 30);
    assert_eq!(a(0)["console_last_used_days"], 2);
    // No keys, password never used: age counts from the last change.
    assert_eq!(a(1)["access_keys_active"], 0);
    assert_eq!(a(1)["unused_key_age_days"], serde_json::Value::Null);
    assert_eq!(a(1)["console_last_used_days"], 293);
}
