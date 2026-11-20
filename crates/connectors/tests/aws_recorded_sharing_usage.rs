//! Template version 3 reads: who a cluster snapshot is shared with, public disk snapshots, and 7-day CPU and traffic.

use aws_sdk_cloudwatch::operation::get_metric_data::GetMetricDataOutput;
use aws_sdk_cloudwatch::types::{MetricDataResult, StatusCode};
use aws_smithy_http_client::test_util::infallible_client_fn;
use aws_smithy_mocks::{mock, mock_client, RuleMode};
use chrono::{DateTime, Duration, Utc};
use opsagent_connectors::aws::inventory::{
    ec2_snapshots, inventory, rds_cluster_snapshots, usage, Target,
};
use opsagent_connectors::{ConnectorError, Scope};
use opsagent_core::resource::{Provider, Resource, ResourceKind};
use serde_json::json;

const T: Target = Target {
    partition: "aws",
    account: "123456789012",
    region: "eu-west-1",
};

mod snapshots {
    use super::*;
    use aws_sdk_ec2::operation::describe_snapshots::DescribeSnapshotsOutput;
    use aws_sdk_ec2::types::Snapshot;
    use aws_sdk_rds::operation::describe_db_cluster_snapshot_attributes::{
        DescribeDBClusterSnapshotAttributesError, DescribeDbClusterSnapshotAttributesOutput,
    };
    use aws_sdk_rds::operation::describe_db_cluster_snapshots::DescribeDbClusterSnapshotsOutput;
    use aws_sdk_rds::types::{
        error::DbClusterSnapshotNotFoundFault, DbClusterSnapshot, DbClusterSnapshotAttribute,
        DbClusterSnapshotAttributesResult,
    };

    /// The listing restorable by `all` holds `public`; the plain owner listing holds `all`.
    fn disk_rules(
        public: &'static [&'static str],
        all: &'static [&'static str],
    ) -> [aws_smithy_mocks::Rule; 2] {
        let list = |ids: &'static [&'static str]| {
            move || {
                let mut out = DescribeSnapshotsOutput::builder();
                for id in ids {
                    out =
                        out.snapshots(Snapshot::builder().snapshot_id(*id).encrypted(true).build());
                }
                out.build()
            }
        };
        [
            mock!(aws_sdk_ec2::Client::describe_snapshots)
                .match_requests(|r| {
                    r.owner_ids() == ["self"] && r.restorable_by_user_ids() == ["all"]
                })
                .then_output(list(public)),
            mock!(aws_sdk_ec2::Client::describe_snapshots)
                .match_requests(|r| {
                    r.owner_ids() == ["self"] && r.restorable_by_user_ids().is_empty()
                })
                .then_output(list(all)),
        ]
    }

    #[tokio::test]
    async fn a_disk_snapshot_is_public_when_the_public_listing_returns_it() {
        let [public, all] = disk_rules(&["snap-public"], &["snap-public", "snap-private"]);
        let ec2 = mock_client!(aws_sdk_ec2, RuleMode::MatchAny, [&public, &all]);
        let r = ec2_snapshots(&ec2, &T).await.unwrap();
        let got: Vec<_> = r
            .iter()
            .map(|r| (r.name.as_str(), r.attributes["public"].clone()))
            .collect();
        assert_eq!(
            got,
            [("snap-public", json!(true)), ("snap-private", json!(false))]
        );
        // One public listing and one plain listing, however many snapshots: no per-snapshot call.
        assert_eq!((public.num_calls(), all.num_calls()), (1, 1));
    }

    #[tokio::test]
    async fn a_failed_public_listing_fails_the_service_never_reports_private() {
        use aws_sdk_ec2::error::ErrorMetadata;
        use aws_sdk_ec2::operation::describe_snapshots::DescribeSnapshotsError;
        let [_, all] = disk_rules(&[], &["snap-1"]);
        let denied = mock!(aws_sdk_ec2::Client::describe_snapshots)
            .match_requests(|r| r.restorable_by_user_ids() == ["all"])
            .then_error(|| {
                DescribeSnapshotsError::generic(
                    ErrorMetadata::builder()
                        .code("UnauthorizedOperation")
                        .build(),
                )
            });
        let ec2 = mock_client!(aws_sdk_ec2, RuleMode::MatchAny, [&denied, &all]);
        let err = ec2_snapshots(&ec2, &T).await.unwrap_err();
        assert!(
            matches!(&err, ConnectorError::Api { code: Some(c), .. } if c == "UnauthorizedOperation"),
            "{err:?}"
        );
    }

    fn cluster_list() -> aws_smithy_mocks::Rule {
        mock!(aws_sdk_rds::Client::describe_db_cluster_snapshots)
            .match_requests(|r| r.snapshot_type() == Some("manual"))
            .then_output(|| {
                let snap = |id: &str| {
                    DbClusterSnapshot::builder()
                        .db_cluster_snapshot_identifier(id)
                        .db_cluster_snapshot_arn(format!(
                            "arn:aws:rds:eu-west-1:123456789012:cluster-snapshot:{id}"
                        ))
                        .storage_encrypted(true)
                        .build()
                };
                DescribeDbClusterSnapshotsOutput::builder()
                    .db_cluster_snapshots(snap("open"))
                    .db_cluster_snapshots(snap("private"))
                    .db_cluster_snapshots(snap("gone"))
                    .build()
            })
    }

    fn cluster_attrs(
        id: &'static str,
        name: &'static str,
        value: &'static str,
    ) -> aws_smithy_mocks::Rule {
        mock!(aws_sdk_rds::Client::describe_db_cluster_snapshot_attributes)
            .match_requests(move |r| r.db_cluster_snapshot_identifier() == Some(id))
            .then_output(move || {
                DescribeDbClusterSnapshotAttributesOutput::builder()
                    .db_cluster_snapshot_attributes_result(
                        DbClusterSnapshotAttributesResult::builder()
                            .db_cluster_snapshot_attributes(
                                DbClusterSnapshotAttribute::builder()
                                    .attribute_name(name)
                                    .attribute_values(value)
                                    .build(),
                            )
                            .build(),
                    )
                    .build()
            })
    }

    #[tokio::test]
    async fn cluster_snapshots_are_public_when_restore_includes_all() {
        let open = cluster_attrs("open", "restore", "all");
        let private = cluster_attrs("private", "restore", "999999999999");
        let gone = mock!(aws_sdk_rds::Client::describe_db_cluster_snapshot_attributes)
            .match_requests(|r| r.db_cluster_snapshot_identifier() == Some("gone"))
            .then_error(|| {
                DescribeDBClusterSnapshotAttributesError::DbClusterSnapshotNotFoundFault(
                    DbClusterSnapshotNotFoundFault::builder().build(),
                )
            });
        let rds = mock_client!(
            aws_sdk_rds,
            RuleMode::MatchAny,
            [&cluster_list(), &open, &private, &gone]
        );
        let r = rds_cluster_snapshots(&rds, &T, true).await.unwrap();
        let got: Vec<_> = r
            .iter()
            .map(|r| (r.name.as_str(), r.attributes["public"].clone()))
            .collect();
        assert_eq!(got, [("open", json!(true)), ("private", json!(false))]);
        assert_eq!(r[0].attributes["encrypted"], true);
    }

    #[tokio::test]
    async fn cluster_snapshot_attributes_are_not_asked_without_the_permission() {
        let rds = mock_client!(aws_sdk_rds, RuleMode::MatchAny, [&cluster_list()]);
        let r = rds_cluster_snapshots(&rds, &T, false).await.unwrap();
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|r| r.attributes["public"].is_null()));
    }

    /// A role that cannot read the sharing attributes (a version 3 connection whose stack was
    /// changed): those two services are partial, with their codes, and nothing else fails.
    #[tokio::test]
    async fn a_denied_cluster_sharing_read_is_partial_for_that_service_only() {
        let http = infallible_client_fn(|req| {
            let (host, body) = (req.uri().host().unwrap_or_default().to_owned(), req.body());
            let body = String::from_utf8_lossy(body.bytes().unwrap_or_default()).into_owned();
            let r = http::Response::builder();
            let ec2 = |inner: &str| {
                format!("<DescribeSnapshotsResponse xmlns=\"http://ec2.amazonaws.com/doc/2016-11-15/\"><requestId>r</requestId>{inner}</DescribeSnapshotsResponse>")
            };
            if host.starts_with("ec2.") {
                return r
                    .status(200)
                    .body(ec2(
                        "<snapshotSet><item><snapshotId>snap-1</snapshotId></item></snapshotSet>",
                    ))
                    .unwrap();
            }
            if body.contains("DescribeDBClusterSnapshotAttributes") {
                return r.status(403).body("<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>no</Message></Error><RequestId>r</RequestId></ErrorResponse>".to_owned()).unwrap();
            }
            r.status(200).body("<DescribeDBClusterSnapshotsResponse xmlns=\"http://rds.amazonaws.com/doc/2014-10-31/\"><DescribeDBClusterSnapshotsResult><DBClusterSnapshots><DBClusterSnapshot><DBClusterSnapshotIdentifier>c-1</DBClusterSnapshotIdentifier></DBClusterSnapshot></DBClusterSnapshots></DescribeDBClusterSnapshotsResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></DescribeDBClusterSnapshotsResponse>".to_owned()).unwrap()
        });
        let session = aws_config::SdkConfig::builder()
            .behavior_version(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::from_static("eu-west-1"))
            .credentials_provider(aws_sdk_sts::config::SharedCredentialsProvider::new(
                aws_sdk_sts::config::Credentials::new("AKID", "secret", None, None, "test"),
            ))
            .retry_config(aws_config::retry::RetryConfig::disabled())
            .http_client(http)
            .build();
        let scope = |services: &[&str]| Scope {
            regions: vec!["eu-west-1".into()],
            services: services.iter().map(|s| s.to_string()).collect(),
        };
        let both = scope(&["ebs_snapshot", "rds_cluster_snapshot"]);
        let r = inventory(&session, "aws", "123456789012", &both, true)
            .await
            .expect("a denied optional read is partial, not a failed connection");
        let mut got: Vec<_> = r
            .partial_errors
            .iter()
            .map(|e| (e.service.as_str(), e.code.as_deref().unwrap_or_default()))
            .collect();
        got.sort();
        assert_eq!(got, [("rds_cluster_snapshot", "AccessDenied")]);
        // The disk snapshots were read and are not public.
        assert_eq!(r.resources.len(), 1);
        // The same role, connection recorded before version 3: no such read, nothing partial.
        let r = inventory(&session, "aws", "123456789012", &both, false)
            .await
            .unwrap();
        assert!(r.partial_errors.is_empty(), "{:?}", r.partial_errors);
        assert_eq!(r.resources.len(), 2);
    }
}

mod usage_reads {
    use super::*;

    fn now() -> DateTime<Utc> {
        "2026-11-20T00:00:00Z".parse().unwrap()
    }

    fn resource(identity: &str, attributes: serde_json::Value) -> Resource {
        Resource {
            provider: Provider::Aws,
            account: "123456789012".into(),
            region: "eu-west-1".into(),
            kind: ResourceKind::Compute,
            identity: identity.into(),
            name: identity.into(),
            tags: Default::default(),
            attributes,
            observed_at: now(),
        }
    }

    fn instance(id: &str, state: &str) -> Resource {
        resource(
            &format!("arn:aws:ec2:eu-west-1:123456789012:instance/{id}"),
            json!({"service": "ec2", "state": state, "cpu_avg_7d": null}),
        )
    }

    fn series(id: &str, values: &[f64], status: StatusCode) -> MetricDataResult {
        MetricDataResult::builder()
            .id(id)
            .set_values(Some(values.to_vec()))
            .status_code(status)
            .build()
    }

    fn answer(results: Vec<MetricDataResult>) -> aws_smithy_mocks::Rule {
        mock!(aws_sdk_cloudwatch::Client::get_metric_data).then_output(move || {
            GetMetricDataOutput::builder()
                .set_metric_data_results(Some(results.clone()))
                .build()
        })
    }

    #[tokio::test]
    async fn cpu_is_one_batch_call_and_missing_data_is_never_zero() {
        let rule = mock!(aws_sdk_cloudwatch::Client::get_metric_data)
            .match_requests(|r| {
                let q = r.metric_data_queries();
                let dim = |i: usize| {
                    q[i].metric_stat().unwrap().metric().unwrap().dimensions()[0]
                        .value()
                        .unwrap_or_default()
                        .to_owned()
                };
                q.len() == 3
                    && dim(0) == "i-busy"
                    && dim(1) == "i-idle"
                    && dim(2) == "i-new"
                    && q[0].metric_stat().unwrap().metric().unwrap().namespace() == Some("AWS/EC2")
                    && q[0].metric_stat().unwrap().stat() == Some("Average")
            })
            .then_output(|| {
                GetMetricDataOutput::builder()
                    .metric_data_results(series("m0", &[60.0; 168], StatusCode::Complete))
                    .metric_data_results(series("m1", &[2.0, 4.0].repeat(84), StatusCode::Complete))
                    // Running a day: too few hours to say "for a week".
                    .metric_data_results(series("m2", &[1.0; 24], StatusCode::Complete))
                    .build()
            });
        let cw = mock_client!(aws_sdk_cloudwatch, RuleMode::Sequential, [&rule]);
        let mut got = Some(Ok(vec![
            instance("i-busy", "running"),
            instance("i-idle", "running"),
            instance("i-stopped", "stopped"),
            instance("i-new", "running"),
        ]));
        assert!(usage::ec2_cpu(&cw, &mut got, now()).await.is_none());
        assert_eq!(rule.num_calls(), 1);
        let cpu: Vec<_> = got
            .unwrap()
            .unwrap()
            .iter()
            .map(|r| r.attributes["cpu_avg_7d"].clone())
            .collect();
        assert_eq!(cpu, [json!(60.0), json!(3.0), json!(null), json!(null)]);
    }

    #[tokio::test]
    async fn cpu_that_cloudwatch_did_not_complete_stays_unknown() {
        let cw = mock_client!(
            aws_sdk_cloudwatch,
            RuleMode::Sequential,
            [&answer(vec![series(
                "m0",
                &[1.0; 168],
                StatusCode::PartialData
            )])]
        );
        let mut got = Some(Ok(vec![instance("i-1", "running")]));
        assert!(usage::ec2_cpu(&cw, &mut got, now()).await.is_none());
        assert_eq!(
            got.unwrap().unwrap()[0].attributes["cpu_avg_7d"],
            json!(null)
        );
    }

    #[tokio::test]
    async fn a_failed_cpu_read_is_reported_and_leaves_null() {
        use aws_sdk_cloudwatch::error::ErrorMetadata;
        use aws_sdk_cloudwatch::operation::get_metric_data::GetMetricDataError;
        let rule = mock!(aws_sdk_cloudwatch::Client::get_metric_data).then_error(|| {
            GetMetricDataError::generic(ErrorMetadata::builder().code("AccessDenied").build())
        });
        let cw = mock_client!(aws_sdk_cloudwatch, RuleMode::Sequential, [&rule]);
        let mut got = Some(Ok(vec![instance("i-1", "running")]));
        let failed = usage::ec2_cpu(&cw, &mut got, now()).await;
        assert!(
            matches!(&failed, Some(ConnectorError::Api { code: Some(c), .. }) if c == "AccessDenied"),
            "{failed:?}"
        );
        assert_eq!(
            got.unwrap().unwrap()[0].attributes["cpu_avg_7d"],
            json!(null)
        );
    }

    #[tokio::test]
    async fn no_running_instance_makes_no_call() {
        let rule = answer(vec![]);
        let cw = mock_client!(aws_sdk_cloudwatch, RuleMode::Sequential, [&rule]);
        let mut got = Some(Ok(vec![instance("i-1", "stopped")]));
        assert!(usage::ec2_cpu(&cw, &mut got, now()).await.is_none());
        assert_eq!(rule.num_calls(), 0);
    }

    fn balancer(kind: &str, name: &str, age_days: i64) -> Resource {
        let lb_type = match kind {
            "app" => "application",
            "net" => "network",
            _ => "gateway",
        };
        resource(
            &format!("arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/{kind}/{name}/abc"),
            json!({
                "service": "elb",
                "lb_type": lb_type,
                "created_at": (now() - Duration::days(age_days)).to_rfc3339(),
                "request_count_7d": null,
                "processed_bytes_7d": null,
            }),
        )
    }

    #[tokio::test]
    async fn traffic_is_a_seven_day_sum_and_no_points_in_a_complete_read_is_zero() {
        let rule = mock!(aws_sdk_cloudwatch::Client::get_metric_data)
            .match_requests(|r| {
                let q = r.metric_data_queries();
                let m = |i: usize| q[i].metric_stat().unwrap().metric().unwrap().clone();
                q.len() == 4
                    && m(0).namespace() == Some("AWS/ApplicationELB")
                    && m(0).metric_name() == Some("RequestCount")
                    && m(0).dimensions()[0].value() == Some("app/busy/abc")
                    && m(2).namespace() == Some("AWS/NetworkELB")
                    && m(2).metric_name() == Some("ProcessedBytes")
                    && m(2).dimensions()[0].value() == Some("net/quiet/abc")
                    && q[0].metric_stat().unwrap().stat() == Some("Sum")
            })
            .then_output(|| {
                GetMetricDataOutput::builder()
                    .metric_data_results(series("m0", &[10.0, 5.0], StatusCode::Complete))
                    .metric_data_results(series("m1", &[], StatusCode::Complete))
                    .metric_data_results(series("m2", &[], StatusCode::Complete))
                    .metric_data_results(series("m3", &[], StatusCode::InternalError))
                    .build()
            });
        let cw = mock_client!(aws_sdk_cloudwatch, RuleMode::Sequential, [&rule]);
        let mut got = Some(Ok(vec![
            balancer("app", "busy", 30),
            balancer("app", "idle", 30),
            balancer("net", "quiet", 30),
            balancer("app", "unread", 30),
            balancer("app", "young", 2),
            balancer("gwy", "mirror", 30),
        ]));
        assert!(usage::lb_traffic(&cw, &mut got, now()).await.is_none());
        assert_eq!(rule.num_calls(), 1);
        let a: Vec<_> = got
            .unwrap()
            .unwrap()
            .into_iter()
            .map(|r| r.attributes)
            .collect();
        assert_eq!(a[0]["request_count_7d"], json!(15));
        assert_eq!(a[1]["request_count_7d"], json!(0));
        assert_eq!(a[2]["processed_bytes_7d"], json!(0));
        assert_eq!(a[2]["request_count_7d"], json!(null));
        for (i, why) in [(3, "unread"), (4, "younger than a week"), (5, "gateway")] {
            assert_eq!(a[i]["request_count_7d"], json!(null), "{why}");
            assert_eq!(a[i]["processed_bytes_7d"], json!(null), "{why}");
        }
    }
}

mod older_roles {
    use super::*;
    use aws_sdk_iam::operation::simulate_principal_policy::SimulatePrincipalPolicyOutput;
    use aws_sdk_iam::types::{EvaluationResult, PolicyEvaluationDecisionType as D};
    use opsagent_connectors::aws::simulate::allows_cluster_snapshot_sharing;

    const ROLE: &str = "arn:aws:iam::123456789012:role/OpsAgentReadRole-abcd1234";

    fn simulated(decision: D) -> aws_sdk_iam::Client {
        let rule = mock!(aws_sdk_iam::Client::simulate_principal_policy)
            .match_requests(|r| {
                r.policy_source_arn() == Some(ROLE)
                    && r.action_names() == ["rds:DescribeDBClusterSnapshotAttributes"]
            })
            .then_output(move || {
                SimulatePrincipalPolicyOutput::builder()
                    .evaluation_results(
                        EvaluationResult::builder()
                            .eval_action_name("rds:DescribeDBClusterSnapshotAttributes")
                            .eval_decision(decision.clone())
                            .build()
                            .unwrap(),
                    )
                    .build()
            });
        mock_client!(aws_sdk_iam, RuleMode::Sequential, [&rule])
    }

    #[tokio::test]
    async fn a_role_is_asked_by_simulation() {
        assert!(allows_cluster_snapshot_sharing(&simulated(D::Allowed), ROLE).await);
        // A version 2 role: the read is not in its policy.
        assert!(!allows_cluster_snapshot_sharing(&simulated(D::ImplicitDeny), ROLE).await);
    }

    #[tokio::test]
    async fn a_failed_simulation_means_not_granted_never_an_error() {
        use aws_sdk_iam::error::ErrorMetadata;
        use aws_sdk_iam::operation::simulate_principal_policy::SimulatePrincipalPolicyError;
        let rule = mock!(aws_sdk_iam::Client::simulate_principal_policy).then_error(|| {
            SimulatePrincipalPolicyError::generic(
                ErrorMetadata::builder().code("AccessDenied").build(),
            )
        });
        let iam = mock_client!(aws_sdk_iam, RuleMode::Sequential, [&rule]);
        assert!(!allows_cluster_snapshot_sharing(&iam, ROLE).await);
    }
}
