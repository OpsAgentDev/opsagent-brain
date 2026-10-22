//! Recorded SDK responses for the Plan 2 capabilities: backups, certificates, log groups,
//! GPU metrics, training jobs, restore simulation, trail delivery.

use aws_smithy_mocks::{mock, mock_client, RuleMode};
use aws_smithy_types::DateTime as SmithyTime;
use chrono::{DateTime, Utc};
use opsagent_connectors::aws::inventory::{
    backups, certificates, cloudtrails, gpu_utilisation, log_groups, mark_backup_coverage,
    training_jobs, Target,
};
use opsagent_connectors::aws::metrics::metric_points;
use opsagent_connectors::aws::simulate::{simulate_restore, RESTORE_ACTIONS};
use opsagent_core::resource::{Provider, Resource, ResourceKind};
use serde_json::json;
use std::collections::BTreeMap;

const T: Target = Target {
    partition: "aws",
    account: "123456789012",
    region: "eu-west-1",
};

fn now() -> DateTime<Utc> {
    "2026-10-01T00:00:00Z".parse().unwrap()
}

fn ts(s: &str) -> SmithyTime {
    SmithyTime::from_secs(s.parse::<DateTime<Utc>>().unwrap().timestamp())
}

#[tokio::test]
async fn backup_plans_jobs_and_vaults_map_to_contract() {
    use aws_sdk_backup::operation::{
        get_backup_plan::GetBackupPlanOutput, list_backup_jobs::ListBackupJobsOutput,
        list_backup_plans::ListBackupPlansOutput, list_backup_vaults::ListBackupVaultsOutput,
    };
    use aws_sdk_backup::types::{
        BackupJob, BackupJobState, BackupPlan, BackupPlansListMember, BackupRule,
        BackupVaultListMember, CopyAction, RecoveryPointCreator,
    };
    let plans = mock!(aws_sdk_backup::Client::list_backup_plans).then_output(|| {
        ListBackupPlansOutput::builder()
            .backup_plans_list(
                BackupPlansListMember::builder()
                    .backup_plan_id("p-ok")
                    .backup_plan_arn("arn:aws:backup:eu-west-1:123456789012:backup-plan:p-ok")
                    .backup_plan_name("nightly")
                    .build(),
            )
            .backup_plans_list(
                BackupPlansListMember::builder()
                    .backup_plan_id("p-bad")
                    .backup_plan_arn("arn:aws:backup:eu-west-1:123456789012:backup-plan:p-bad")
                    .backup_plan_name("weekly")
                    .build(),
            )
            .build()
    });
    let job = |plan: &str, res: &str, state: BackupJobState, at: &str| {
        BackupJob::builder()
            .resource_arn(res)
            .state(state)
            .creation_date(ts(at))
            .iam_role_arn("arn:aws:iam::123456789012:role/backup")
            .created_by(RecoveryPointCreator::builder().backup_plan_id(plan).build())
            .build()
    };
    let db1 = "arn:aws:rds:eu-west-1:123456789012:db:db-1";
    let db2 = "arn:aws:rds:eu-west-1:123456789012:db:db-2";
    let jobs = mock!(aws_sdk_backup::Client::list_backup_jobs)
        .match_requests(|r| r.by_created_after().is_some())
        .then_output(move || {
            ListBackupJobsOutput::builder()
                .backup_jobs(job(
                    "p-ok",
                    db1,
                    BackupJobState::Completed,
                    "2026-09-29T00:00:00Z",
                ))
                .backup_jobs(job(
                    "p-ok",
                    db1,
                    BackupJobState::Completed,
                    "2026-09-30T00:00:00Z",
                ))
                .backup_jobs(job(
                    "p-bad",
                    db2,
                    BackupJobState::Completed,
                    "2026-09-20T00:00:00Z",
                ))
                .backup_jobs(job(
                    "p-bad",
                    db2,
                    BackupJobState::Failed,
                    "2026-09-27T00:00:00Z",
                ))
                .build()
        });
    let rule = |copy: Option<&str>| {
        let mut b = BackupRule::builder()
            .rule_name("r")
            .target_backup_vault_name("Default");
        if let Some(arn) = copy {
            b = b.copy_actions(
                CopyAction::builder()
                    .destination_backup_vault_arn(arn)
                    .build()
                    .unwrap(),
            );
        }
        b.build().unwrap()
    };
    let other = "arn:aws:backup:eu-west-1:999999999999:backup-vault:offsite";
    let get_ok = mock!(aws_sdk_backup::Client::get_backup_plan)
        .match_requests(|r| r.backup_plan_id() == Some("p-ok"))
        .then_output(move || {
            GetBackupPlanOutput::builder()
                .backup_plan(
                    BackupPlan::builder()
                        .backup_plan_name("nightly")
                        .rules(rule(Some(other)))
                        .build()
                        .unwrap(),
                )
                .build()
        });
    let get_bad = mock!(aws_sdk_backup::Client::get_backup_plan)
        .match_requests(|r| r.backup_plan_id() == Some("p-bad"))
        .then_output(move || {
            GetBackupPlanOutput::builder()
                .backup_plan(
                    BackupPlan::builder()
                        .backup_plan_name("weekly")
                        .rules(rule(None))
                        .build()
                        .unwrap(),
                )
                .build()
        });
    let vaults = mock!(aws_sdk_backup::Client::list_backup_vaults).then_output(|| {
        ListBackupVaultsOutput::builder()
            .backup_vault_list(
                BackupVaultListMember::builder()
                    .backup_vault_name("Default")
                    .backup_vault_arn("arn:aws:backup:eu-west-1:123456789012:backup-vault:Default")
                    .build(),
            )
            .build()
    });
    let b = mock_client!(
        aws_sdk_backup,
        RuleMode::MatchAny,
        [&plans, &jobs, &get_ok, &get_bad, &vaults]
    );
    let r = backups(&b, &T, now()).await.unwrap();
    let find = |id: &str| r.iter().find(|x| x.identity == id).unwrap();
    let ok = find("arn:aws:backup:eu-west-1:123456789012:backup-plan:p-ok");
    assert_eq!(ok.name, "nightly");
    assert_eq!(
        ok.attributes,
        json!({"service": "backup", "plan": true, "selections": [db1],
               "last_job_status": "COMPLETED", "last_job_at": "2026-09-30T00:00:00Z",
               "iam_role_arns": ["arn:aws:iam::123456789012:role/backup"]})
    );
    let bad = find("arn:aws:backup:eu-west-1:123456789012:backup-plan:p-bad");
    assert_eq!(bad.attributes["last_job_status"], "FAILED");
    assert_eq!(bad.attributes["selections"], json!([db2]));
    assert_eq!(
        find("arn:aws:backup:eu-west-1:123456789012:backup-vault:Default").attributes,
        json!({"service": "backup", "vault": true, "cross_account": false})
    );
    assert_eq!(
        find(other).attributes,
        json!({"service": "backup", "vault": true, "cross_account": true})
    );
    assert!(r
        .iter()
        .all(|x| x.provider == Provider::Aws && x.region == "eu-west-1"));

    // Coverage marks RDS instances the plans' jobs touched.
    let rds = |id: &str| Resource {
        provider: Provider::Aws,
        account: T.account.into(),
        region: T.region.into(),
        kind: ResourceKind::Database,
        identity: id.into(),
        name: id.into(),
        tags: BTreeMap::new(),
        attributes: json!({"service": "rds", "in_backup_plan": null}),
        observed_at: now(),
    };
    let mut dbs = vec![rds(db1), rds("arn:aws:rds:eu-west-1:123456789012:db:db-3")];
    mark_backup_coverage(&mut dbs, &r);
    assert_eq!(dbs[0].attributes["in_backup_plan"], true);
    assert_eq!(dbs[1].attributes["in_backup_plan"], false);
}

#[tokio::test]
async fn describe_certificate_maps_expiry_renewal_use_and_management() {
    use aws_sdk_acm::operation::{
        describe_certificate::DescribeCertificateOutput, list_certificates::ListCertificatesOutput,
    };
    use aws_sdk_acm::types::{
        CertificateDetail, CertificateSummary, CertificateType, RenewalStatus, RenewalSummary,
    };
    let a = "arn:aws:acm:eu-west-1:123456789012:certificate/a";
    let b = "arn:aws:acm:eu-west-1:123456789012:certificate/b";
    let list = mock!(aws_sdk_acm::Client::list_certificates).then_output(move || {
        ListCertificatesOutput::builder()
            .certificate_summary_list(CertificateSummary::builder().certificate_arn(a).build())
            .certificate_summary_list(CertificateSummary::builder().certificate_arn(b).build())
            .build()
    });
    let da = mock!(aws_sdk_acm::Client::describe_certificate)
        .match_requests(move |r| r.certificate_arn() == Some(a))
        .then_output(move || {
            DescribeCertificateOutput::builder()
                .certificate(
                    CertificateDetail::builder()
                        .certificate_arn(a)
                        .domain_name("api.example.com")
                        .not_after(ts("2026-10-06T00:00:00Z"))
                        .r#type(CertificateType::AmazonIssued)
                        .in_use_by("arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/web/1")
                        .renewal_summary(
                            RenewalSummary::builder()
                                .renewal_status(RenewalStatus::Failed)
                                .set_domain_validation_options(Some(vec![]))
                                .updated_at(ts("2026-09-30T00:00:00Z"))
                                .build()
                                .unwrap(),
                        )
                        .build(),
                )
                .build()
        });
    let db = mock!(aws_sdk_acm::Client::describe_certificate)
        .match_requests(move |r| r.certificate_arn() == Some(b))
        .then_output(move || {
            DescribeCertificateOutput::builder()
                .certificate(
                    CertificateDetail::builder()
                        .certificate_arn(b)
                        .domain_name("old.example.com")
                        .not_after(ts("2027-04-19T00:00:00Z"))
                        .r#type(CertificateType::Imported)
                        .build(),
                )
                .build()
        });
    let acm = mock_client!(aws_sdk_acm, RuleMode::MatchAny, [&list, &da, &db]);
    let r = certificates(&acm, &T).await.unwrap();
    assert_eq!(r.len(), 2);
    assert!(r.iter().all(|x| x.kind == ResourceKind::Certificate));
    assert_eq!(r[0].identity, a);
    assert_eq!(r[0].name, "api.example.com");
    assert_eq!(
        r[0].attributes,
        json!({"service": "acm", "not_after": "2026-10-06T00:00:00Z", "renewal_status": "FAILED",
               "in_use_by": ["arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/web/1"],
               "managed": true})
    );
    assert_eq!(
        r[1].attributes,
        json!({"service": "acm", "not_after": "2027-04-19T00:00:00Z", "renewal_status": null,
               "in_use_by": [], "managed": false})
    );
}

#[tokio::test]
async fn describe_log_groups_maps_retention_and_bytes() {
    use aws_sdk_cloudwatchlogs::operation::describe_log_groups::DescribeLogGroupsOutput;
    use aws_sdk_cloudwatchlogs::types::LogGroup;
    let rule = mock!(aws_sdk_cloudwatchlogs::Client::describe_log_groups).then_output(|| {
        DescribeLogGroupsOutput::builder()
            .log_groups(
                LogGroup::builder()
                    .log_group_name("/app/api")
                    .log_group_arn("arn:aws:logs:eu-west-1:123456789012:log-group:/app/api")
                    .stored_bytes(50_000_000_000)
                    .build(),
            )
            .log_groups(
                LogGroup::builder()
                    .log_group_name("/app/web")
                    .arn("arn:aws:logs:eu-west-1:123456789012:log-group:/app/web:*")
                    .retention_in_days(30)
                    .stored_bytes(10)
                    .build(),
            )
            .build()
    });
    let logs = mock_client!(aws_sdk_cloudwatchlogs, RuleMode::Sequential, [&rule]);
    let r = log_groups(&logs, &T).await.unwrap();
    assert_eq!(r.len(), 2);
    assert!(r.iter().all(|x| x.kind == ResourceKind::Log));
    assert_eq!(
        r[0].identity,
        "arn:aws:logs:eu-west-1:123456789012:log-group:/app/api"
    );
    assert_eq!(
        r[0].attributes,
        json!({"service": "logs", "retention_days": null, "stored_bytes": 50_000_000_000u64})
    );
    assert_eq!(
        r[1].identity,
        "arn:aws:logs:eu-west-1:123456789012:log-group:/app/web"
    );
    assert_eq!(r[1].attributes["retention_days"], 30);
}

#[tokio::test]
async fn trail_with_delivery_error_is_not_writable() {
    use aws_sdk_cloudtrail::operation::{
        describe_trails::DescribeTrailsOutput, get_trail_status::GetTrailStatusOutput,
    };
    use aws_sdk_cloudtrail::types::Trail;
    let arn = "arn:aws:cloudtrail:eu-west-1:123456789012:trail/main";
    let d = mock!(aws_sdk_cloudtrail::Client::describe_trails).then_output(move || {
        DescribeTrailsOutput::builder()
            .trail_list(Trail::builder().name("main").trail_arn(arn).build())
            .build()
    });
    let s = mock!(aws_sdk_cloudtrail::Client::get_trail_status).then_output(|| {
        GetTrailStatusOutput::builder()
            .is_logging(true)
            .latest_delivery_error("AccessDenied")
            .build()
    });
    let ct = mock_client!(aws_sdk_cloudtrail, RuleMode::Sequential, [&d, &s]);
    let r = cloudtrails(&ct, &T).await.unwrap();
    assert_eq!(
        r[0].attributes,
        json!({"service": "cloudtrail", "logging": true, "bucket_writable": false})
    );
}

fn metric_output(
    values: &[(&str, f64)],
) -> aws_sdk_cloudwatch::operation::get_metric_data::GetMetricDataOutput {
    use aws_sdk_cloudwatch::types::MetricDataResult;
    aws_sdk_cloudwatch::operation::get_metric_data::GetMetricDataOutput::builder()
        .metric_data_results(
            MetricDataResult::builder()
                .id("m")
                .set_timestamps(Some(values.iter().map(|(t, _)| ts(t)).collect()))
                .set_values(Some(values.iter().map(|(_, v)| *v).collect()))
                .build(),
        )
        .build()
}

#[tokio::test]
async fn get_metric_data_maps_cpu_and_gpu_queries() {
    let cpu = mock!(aws_sdk_cloudwatch::Client::get_metric_data)
        .match_requests(|r| {
            let q = &r.metric_data_queries()[0];
            let m = q.metric_stat().and_then(|s| s.metric());
            m.and_then(|m| m.namespace()) == Some("AWS/EC2")
                && m.and_then(|m| m.metric_name()) == Some("CPUUtilization")
                && m.map(|m| m.dimensions()[0].value()) == Some(Some("i-0abc"))
                && r.start_time() == Some(&ts("2026-09-30T00:00:00Z"))
        })
        .then_output(|| {
            metric_output(&[("2026-09-30T01:00:00Z", 3.0), ("2026-09-30T00:00:00Z", 1.0)])
        });
    let gpu = mock!(aws_sdk_cloudwatch::Client::get_metric_data)
        .match_requests(|r| {
            r.metric_data_queries()[0].expression().is_some_and(|e| {
                e.contains("CWAgent")
                    && e.contains("nvidia_smi_utilization_gpu")
                    && e.contains("i-0abc")
            })
        })
        .then_output(|| metric_output(&[]));
    let cw = mock_client!(aws_sdk_cloudwatch, RuleMode::MatchAny, [&cpu, &gpu]);
    let p = metric_points(&cw, "i-0abc", "cpu_avg", 24, now())
        .await
        .unwrap();
    assert_eq!(p.len(), 2);
    assert!(p[0].at < p[1].at, "sorted by time");
    assert_eq!(p[0].value, 1.0);
    assert!(metric_points(&cw, "i-0abc", "gpu_util_avg", 24, now())
        .await
        .unwrap()
        .is_empty());
    assert!(metric_points(&cw, "i-0abc", "disk", 24, now())
        .await
        .is_err());
    assert!(metric_points(&cw, "i-0abc\"')", "cpu_avg", 24, now())
        .await
        .is_err());
}

#[tokio::test]
async fn gpu_utilisation_sets_24h_average_on_accelerated_only() {
    let gpu = mock!(aws_sdk_cloudwatch::Client::get_metric_data).then_output(|| {
        metric_output(&[("2026-09-30T00:00:00Z", 1.0), ("2026-09-30T01:00:00Z", 3.0)])
    });
    let cw = mock_client!(aws_sdk_cloudwatch, RuleMode::MatchAny, [&gpu]);
    let inst = |id: &str, acc: bool| Resource {
        provider: Provider::Aws,
        account: T.account.into(),
        region: T.region.into(),
        kind: ResourceKind::Compute,
        identity: format!("arn:aws:ec2:eu-west-1:123456789012:instance/{id}"),
        name: id.into(),
        tags: BTreeMap::new(),
        attributes: json!({"service": "ec2", "accelerated": acc, "state": "running"}),
        observed_at: now(),
    };
    let mut v = vec![inst("i-gpu", true), inst("i-cpu", false)];
    gpu_utilisation(&cw, &mut v, now()).await.unwrap();
    assert_eq!(v[0].attributes["gpu_util_24h"], 2.0);
    assert!(v[1].attributes.get("gpu_util_24h").is_none());
    assert_eq!(gpu.num_calls(), 1);
}

#[tokio::test]
async fn list_training_jobs_maps_in_progress_with_median_history() {
    use aws_sdk_sagemaker::operation::list_training_jobs::ListTrainingJobsOutput;
    use aws_sdk_sagemaker::types::{TrainingJobStatus, TrainingJobSummary};
    let job = |name: &str, status: TrainingJobStatus, start: &str, end: Option<&str>| {
        TrainingJobSummary::builder()
            .training_job_name(name)
            .training_job_arn(format!(
                "arn:aws:sagemaker:eu-west-1:123456789012:training-job/{name}"
            ))
            .training_job_status(status)
            .creation_time(ts(start))
            .set_training_end_time(end.map(ts))
            .build()
    };
    let running = mock!(aws_sdk_sagemaker::Client::list_training_jobs)
        .match_requests(|r| r.status_equals() == Some(&TrainingJobStatus::InProgress))
        .then_output(move || {
            ListTrainingJobsOutput::builder()
                .training_job_summaries(job(
                    "resnet-20260929",
                    TrainingJobStatus::InProgress,
                    "2026-09-29T18:00:00Z",
                    None,
                ))
                .training_job_summaries(job(
                    "fresh-1",
                    TrainingJobStatus::InProgress,
                    "2026-09-29T18:00:00Z",
                    None,
                ))
                .build()
        });
    let history = mock!(aws_sdk_sagemaker::Client::list_training_jobs)
        .match_requests(|r| {
            r.status_equals() == Some(&TrainingJobStatus::Completed)
                && r.name_contains() == Some("resnet")
        })
        .then_output(move || {
            ListTrainingJobsOutput::builder()
                // 6 h, 4 h, 8 h: median 6 h. The last one only contains the prefix.
                .training_job_summaries(job(
                    "resnet-1",
                    TrainingJobStatus::Completed,
                    "2026-09-01T00:00:00Z",
                    Some("2026-09-01T06:00:00Z"),
                ))
                .training_job_summaries(job(
                    "resnet-2",
                    TrainingJobStatus::Completed,
                    "2026-09-02T00:00:00Z",
                    Some("2026-09-02T04:00:00Z"),
                ))
                .training_job_summaries(job(
                    "resnet-3",
                    TrainingJobStatus::Completed,
                    "2026-09-03T00:00:00Z",
                    Some("2026-09-03T08:00:00Z"),
                ))
                .training_job_summaries(job(
                    "old-resnet-9",
                    TrainingJobStatus::Completed,
                    "2026-09-03T00:00:00Z",
                    Some("2026-09-04T08:00:00Z"),
                ))
                .build()
        });
    let none = mock!(aws_sdk_sagemaker::Client::list_training_jobs)
        .match_requests(|r| {
            r.status_equals() == Some(&TrainingJobStatus::Completed)
                && r.name_contains() == Some("fresh")
        })
        .then_output(|| ListTrainingJobsOutput::builder().build());
    let sm = mock_client!(
        aws_sdk_sagemaker,
        RuleMode::MatchAny,
        [&running, &history, &none]
    );
    let r = training_jobs(&sm, &T).await.unwrap();
    assert_eq!(r.len(), 2);
    assert!(r.iter().all(|x| x.kind == ResourceKind::Job));
    assert_eq!(
        r[0].identity,
        "arn:aws:sagemaker:eu-west-1:123456789012:training-job/resnet-20260929"
    );
    assert_eq!(
        r[0].attributes,
        json!({"service": "sagemaker", "job": true, "status": "InProgress",
               "started_at": "2026-09-29T18:00:00Z", "median_runtime_s": 21600})
    );
    assert_eq!(r[1].attributes["median_runtime_s"], json!(null));
}

#[tokio::test]
async fn simulate_restore_splits_allowed_and_denied() {
    use aws_sdk_iam::operation::simulate_principal_policy::SimulatePrincipalPolicyOutput;
    use aws_sdk_iam::types::{EvaluationResult, PolicyEvaluationDecisionType as D};
    let role = "arn:aws:iam::123456789012:role/backup-restore";
    let rule = mock!(aws_sdk_iam::Client::simulate_principal_policy)
        .match_requests(move |r| {
            r.policy_source_arn() == Some(role) && r.action_names() == RESTORE_ACTIONS
        })
        .then_output(|| {
            let e = |a: &str, d: D| {
                EvaluationResult::builder()
                    .eval_action_name(a)
                    .eval_decision(d)
                    .build()
                    .unwrap()
            };
            SimulatePrincipalPolicyOutput::builder()
                .evaluation_results(e("backup:StartRestoreJob", D::Allowed))
                .evaluation_results(e("kms:CreateGrant", D::ImplicitDeny))
                .evaluation_results(e("kms:Decrypt", D::ExplicitDeny))
                .evaluation_results(e("rds:RestoreDBInstanceFromDBSnapshot", D::Allowed))
                .evaluation_results(e("ec2:RunInstances", D::Allowed))
                .build()
        });
    let iam = mock_client!(aws_sdk_iam, RuleMode::Sequential, [&rule]);
    let r = simulate_restore(&iam, role).await.unwrap();
    assert_eq!(r.denied, vec!["kms:CreateGrant", "kms:Decrypt"]);
    assert_eq!(
        r.allowed,
        vec![
            "backup:StartRestoreJob",
            "ec2:RunInstances",
            "rds:RestoreDBInstanceFromDBSnapshot"
        ]
    );
}
