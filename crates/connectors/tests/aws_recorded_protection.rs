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

fn plan_member(id: &str, name: &str) -> aws_sdk_backup::types::BackupPlansListMember {
    aws_sdk_backup::types::BackupPlansListMember::builder()
        .backup_plan_id(id)
        .backup_plan_arn(format!(
            "arn:aws:backup:eu-west-1:123456789012:backup-plan:{id}"
        ))
        .backup_plan_name(name)
        .build()
}

type SelBuilder = aws_sdk_backup::types::builders::BackupSelectionBuilder;

/// One selection per plan, `sel-<plan>`, shaped by `shape`.
fn selection_rules(
    plan: &'static str,
    shape: fn(SelBuilder) -> SelBuilder,
) -> [aws_smithy_mocks::Rule; 2] {
    use aws_sdk_backup::operation::{
        get_backup_selection::GetBackupSelectionOutput,
        list_backup_selections::ListBackupSelectionsOutput,
    };
    use aws_sdk_backup::types::{BackupSelection, BackupSelectionsListMember};
    let list = mock!(aws_sdk_backup::Client::list_backup_selections)
        .match_requests(move |r| r.backup_plan_id() == Some(plan))
        .then_output(move || {
            ListBackupSelectionsOutput::builder()
                .backup_selections_list(
                    BackupSelectionsListMember::builder()
                        .selection_id(format!("sel-{plan}"))
                        .build(),
                )
                .build()
        });
    let get = mock!(aws_sdk_backup::Client::get_backup_selection)
        .match_requests(move |r| r.selection_id() == Some(&format!("sel-{plan}")))
        .then_output(move || {
            let sel = BackupSelection::builder()
                .selection_name("s")
                .iam_role_arn("arn:aws:iam::123456789012:role/backup");
            GetBackupSelectionOutput::builder()
                .backup_selection(shape(sel).build().unwrap())
                .build()
        });
    [list, get]
}

const DB1: &str = "arn:aws:rds:eu-west-1:123456789012:db:db-1";
const DB2: &str = "arn:aws:rds:eu-west-1:123456789012:db:db-2";
const DB5: &str = "arn:aws:rds:eu-west-1:123456789012:db:db-5";
const DB_NEW: &str = "arn:aws:rds:eu-west-1:123456789012:db:db-new";
const DB_OLD: &str = "arn:aws:rds:eu-west-1:123456789012:db:db-old";
const DB_EXCL: &str = "arn:aws:rds:eu-west-1:123456789012:db:db-excluded";
const DB_COND: &str = "arn:aws:rds:eu-west-1:123456789012:db:db-cond";
const DB_JOB: &str = "arn:aws:rds:eu-west-1:123456789012:db:db-job";

fn ok_selection(b: SelBuilder) -> SelBuilder {
    b.resources(DB1)
        .resources(DB5)
        .resources(DB_EXCL)
        .not_resources(DB_EXCL)
}

fn tag_selection(b: SelBuilder) -> SelBuilder {
    use aws_sdk_backup::types::{Condition, ConditionType};
    b.resources("arn:aws:rds:*:*:db:*").list_of_tags(
        Condition::builder()
            .condition_type(ConditionType::Stringequals)
            .condition_key("backup")
            .condition_value("yes")
            .build()
            .unwrap(),
    )
}

/// Explicit ARN narrowed by Conditions: the ARN alone is not trusted.
fn conditioned_selection(b: SelBuilder) -> SelBuilder {
    use aws_sdk_backup::types::{ConditionParameter, Conditions};
    b.resources(DB_COND).conditions(
        Conditions::builder()
            .string_equals(
                ConditionParameter::builder()
                    .condition_key("aws:ResourceTag/backup")
                    .condition_value("yes")
                    .build(),
            )
            .build(),
    )
}

fn new_selection(b: SelBuilder) -> SelBuilder {
    b.resources(DB_NEW)
}

#[tokio::test]
async fn backup_plans_selections_jobs_and_vaults_map_to_contract() {
    use aws_sdk_backup::operation::{
        get_backup_plan::GetBackupPlanOutput, list_backup_jobs::ListBackupJobsOutput,
        list_backup_plans::ListBackupPlansOutput, list_backup_vaults::ListBackupVaultsOutput,
    };
    use aws_sdk_backup::types::{
        BackupJob, BackupJobState as S, BackupPlan, BackupRule, BackupVaultListMember, CopyAction,
        RecoveryPointCreator,
    };
    let plans = mock!(aws_sdk_backup::Client::list_backup_plans).then_output(|| {
        ListBackupPlansOutput::builder()
            .backup_plans_list(plan_member("p-ok", "nightly"))
            .backup_plans_list(plan_member("p-bad", "weekly"))
            .backup_plans_list(plan_member("p-new", "fresh"))
            .backup_plans_list(plan_member("p-cond", "tagged"))
            .build()
    });
    let job = |plan: &str, res: &str, state: S, at: &str| {
        BackupJob::builder()
            .resource_arn(res)
            .state(state)
            .creation_date(ts(at))
            .created_by(RecoveryPointCreator::builder().backup_plan_id(plan).build())
            .build()
    };
    let jobs = mock!(aws_sdk_backup::Client::list_backup_jobs)
        .match_requests(|r| r.by_created_after().is_some())
        .then_output(move || {
            ListBackupJobsOutput::builder()
                .backup_jobs(job("p-ok", DB1, S::Completed, "2026-09-29T00:00:00Z"))
                .backup_jobs(job("p-ok", DB1, S::Completed, "2026-09-30T00:00:00Z"))
                // Still running: no outcome, does not move last_job_at.
                .backup_jobs(job("p-ok", DB1, S::Running, "2026-09-30T12:00:00Z"))
                // Same plan, another resource failed.
                .backup_jobs(job("p-ok", DB5, S::Failed, "2026-09-30T01:00:00Z"))
                // db-old was removed from p-ok; its failure no longer counts.
                .backup_jobs(job("p-ok", DB_OLD, S::Failed, "2026-09-30T06:00:00Z"))
                .backup_jobs(job("p-ok", DB_EXCL, S::Completed, "2026-09-30T06:00:00Z"))
                .backup_jobs(job("p-bad", DB2, S::Completed, "2026-09-20T00:00:00Z"))
                .backup_jobs(job("p-bad", DB2, S::Aborted, "2026-09-27T00:00:00Z"))
                .backup_jobs(job("p-cond", DB_JOB, S::Completed, "2026-09-28T00:00:00Z"))
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
    let get_plan = mock!(aws_sdk_backup::Client::get_backup_plan).then_output(move || {
        GetBackupPlanOutput::builder()
            .backup_plan(
                BackupPlan::builder()
                    .backup_plan_name("any")
                    .rules(rule(Some(other)))
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
    let [ok_l, ok_g] = selection_rules("p-ok", ok_selection);
    let [bad_l, bad_g] = selection_rules("p-bad", tag_selection);
    let [new_l, new_g] = selection_rules("p-new", new_selection);
    let [cond_l, cond_g] = selection_rules("p-cond", conditioned_selection);
    let b = mock_client!(
        aws_sdk_backup,
        RuleMode::MatchAny,
        [
            &plans, &jobs, &get_plan, &vaults, &ok_l, &ok_g, &bad_l, &bad_g, &new_l, &new_g,
            &cond_l, &cond_g
        ]
    );
    let r = backups(&b, &T, now()).await.unwrap();
    let find = |id: &str| r.iter().find(|x| x.identity.ends_with(id)).unwrap();
    assert_eq!(find(":p-ok").name, "nightly");
    // NotResources removes db-excluded; plan-level status is FAILED (db-5).
    assert_eq!(
        find(":p-ok").attributes,
        json!({"service": "backup", "plan": true, "selections": [DB1, DB5],
               "last_job_status": "FAILED", "last_job_at": "2026-09-30T01:00:00Z",
               "iam_role_arns": ["arn:aws:iam::123456789012:role/backup"],
               "resource_jobs": {
                   DB1: {"status": "COMPLETED", "at": "2026-09-30T00:00:00Z"},
                   DB5: {"status": "FAILED", "at": "2026-09-30T01:00:00Z"}}})
    );
    // Wildcard selection: covered through its job; ABORTED normalises to FAILED.
    let bad = &find(":p-bad").attributes;
    assert_eq!(bad["last_job_status"], "FAILED");
    assert_eq!(bad["selections"], json!([DB2]));
    // Selected, never ran in the window.
    let new = &find(":p-new").attributes;
    assert_eq!(new["selections"], json!([DB_NEW]));
    assert_eq!(new["last_job_status"], json!(null));
    assert_eq!(new["last_job_at"], json!(null));
    // Conditions: the explicit ARN is not trusted, the job's resource is.
    assert_eq!(find(":p-cond").attributes["selections"], json!([DB_JOB]));
    assert_eq!(
        find(":backup-vault:Default").attributes,
        json!({"service": "backup", "vault": true, "cross_account": false})
    );
    assert_eq!(
        find(other).attributes,
        json!({"service": "backup", "vault": true, "cross_account": true})
    );
    assert!(r
        .iter()
        .all(|x| x.provider == Provider::Aws && x.region == "eu-west-1"));

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
    let ids = [DB1, DB5, DB2, DB_NEW, DB_OLD, DB_EXCL, DB_COND, DB_JOB];
    let mut dbs: Vec<Resource> = ids.map(rds).to_vec();
    mark_backup_coverage(&mut dbs, &r);
    let got: Vec<_> = dbs
        .iter()
        .map(|d| {
            let a = &d.attributes;
            (
                a["in_backup_plan"].clone(),
                a["backup_last_job_status"].clone(),
            )
        })
        .collect();
    let want = |c: bool, s: serde_json::Value| (json!(c), s);
    assert_eq!(
        got,
        [
            want(true, json!("COMPLETED")),
            want(true, json!("FAILED")),
            want(true, json!("FAILED")),
            want(true, json!(null)),
            want(false, json!(null)),
            want(false, json!(null)),
            want(false, json!(null)),
            want(true, json!("COMPLETED")),
        ]
    );
    assert_eq!(
        dbs[1].attributes["backup_last_job_at"],
        "2026-09-30T01:00:00Z"
    );
}

#[tokio::test]
async fn describe_certificate_maps_expiry_renewal_use_and_management() {
    use aws_sdk_acm::operation::{
        describe_certificate::DescribeCertificateOutput, list_certificates::ListCertificatesOutput,
    };
    use aws_sdk_acm::types::{
        CertificateDetail, CertificateSummary, CertificateType, KeyAlgorithm, RenewalStatus,
        RenewalSummary,
    };
    let a = "arn:aws:acm:eu-west-1:123456789012:certificate/a";
    let b = "arn:aws:acm:eu-west-1:123456789012:certificate/b";
    let ec = "arn:aws:acm:eu-west-1:123456789012:certificate/ec";
    let broken = "arn:aws:acm:eu-west-1:123456789012:certificate/broken";
    let list = mock!(aws_sdk_acm::Client::list_certificates)
        .match_requests(|r| {
            r.includes().is_some_and(|f| {
                f.key_types().len() == 7 && f.key_types().contains(&KeyAlgorithm::EcPrime256v1)
            })
        })
        .then_output(move || {
            let c = |arn: &str| CertificateSummary::builder().certificate_arn(arn).build();
            ListCertificatesOutput::builder()
                .certificate_summary_list(c(a))
                .certificate_summary_list(c(broken))
                .certificate_summary_list(c(b))
                .certificate_summary_list(c(ec))
                .build()
        });
    let dbroken = mock!(aws_sdk_acm::Client::describe_certificate)
        .match_requests(move |r| r.certificate_arn() == Some(broken))
        .then_error(|| {
            aws_sdk_acm::operation::describe_certificate::DescribeCertificateError::generic(
                aws_sdk_acm::error::ErrorMetadata::builder()
                    .code("ThrottlingException")
                    .message("arn:aws:acm:... secret text")
                    .build(),
            )
        });
    let dec = mock!(aws_sdk_acm::Client::describe_certificate)
        .match_requests(move |r| r.certificate_arn() == Some(ec))
        .then_output(move || {
            DescribeCertificateOutput::builder()
                .certificate(
                    CertificateDetail::builder()
                        .certificate_arn(ec)
                        .domain_name("ec.example.com")
                        .key_algorithm(KeyAlgorithm::EcPrime256v1)
                        .not_after(ts("2027-01-01T00:00:00Z"))
                        .r#type(CertificateType::AmazonIssued)
                        .build(),
                )
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
    let acm = mock_client!(
        aws_sdk_acm,
        RuleMode::MatchAny,
        [&list, &da, &db, &dbroken, &dec]
    );
    let mut errs = vec![];
    let r = certificates(&acm, &T, &mut errs).await.unwrap();
    assert_eq!(
        r.len(),
        3,
        "the failed describe is skipped, the rest return"
    );
    assert_eq!(errs.len(), 1);
    assert_eq!(errs[0].service, "acm");
    assert_eq!(errs[0].code.as_deref(), Some("ThrottlingException"));
    assert_eq!(r[2].name, "ec.example.com");
    assert_eq!(r[2].attributes["managed"], true);
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
    assert!(gpu_utilisation(&cw, &mut v, now()).await.is_none());
    assert_eq!(v[0].attributes["gpu_util_24h"], 2.0);
    assert!(v[1].attributes.get("gpu_util_24h").is_none());
    assert_eq!(gpu.num_calls(), 1);
}

#[tokio::test]
async fn failed_gpu_read_is_null_and_the_rest_continue() {
    use aws_sdk_cloudwatch::operation::get_metric_data::GetMetricDataError;
    let fail = mock!(aws_sdk_cloudwatch::Client::get_metric_data)
        .match_requests(|r| {
            r.metric_data_queries()[0]
                .expression()
                .is_some_and(|e| e.contains("i-bad"))
        })
        .then_error(|| {
            GetMetricDataError::generic(
                aws_sdk_cloudwatch::error::ErrorMetadata::builder()
                    .code("AccessDenied")
                    .build(),
            )
        });
    let ok = mock!(aws_sdk_cloudwatch::Client::get_metric_data)
        .then_output(|| metric_output(&[("2026-09-30T00:00:00Z", 4.0)]));
    let cw = mock_client!(aws_sdk_cloudwatch, RuleMode::MatchAny, [&fail, &ok]);
    let inst = |id: &str| Resource {
        provider: Provider::Aws,
        account: T.account.into(),
        region: T.region.into(),
        kind: ResourceKind::Compute,
        identity: format!("arn:aws:ec2:eu-west-1:123456789012:instance/{id}"),
        name: id.into(),
        tags: BTreeMap::new(),
        attributes: json!({"service": "ec2", "accelerated": true, "state": "running"}),
        observed_at: now(),
    };
    let mut v = vec![inst("i-bad"), inst("i-good")];
    let err = gpu_utilisation(&cw, &mut v, now()).await.unwrap();
    assert_eq!(err.code(), "AccessDenied");
    assert_eq!(v[0].attributes["gpu_util_24h"], json!(null));
    assert_eq!(v[1].attributes["gpu_util_24h"], 4.0);
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

fn eval(
    action: &str,
    d: aws_sdk_iam::types::PolicyEvaluationDecisionType,
    missing: &[&str],
) -> aws_sdk_iam::types::EvaluationResult {
    aws_sdk_iam::types::EvaluationResult::builder()
        .eval_action_name(action)
        .eval_decision(d)
        .set_missing_context_values(Some(missing.iter().map(|m| m.to_string()).collect()))
        .build()
        .unwrap()
}

/// A client answering SimulatePrincipalPolicy for `ROLE` with `results`, checking the request.
fn simulate_client(results: Vec<aws_sdk_iam::types::EvaluationResult>) -> aws_sdk_iam::Client {
    use aws_sdk_iam::operation::simulate_principal_policy::SimulatePrincipalPolicyOutput;
    let rule = mock!(aws_sdk_iam::Client::simulate_principal_policy)
        .match_requests(|r| {
            r.policy_source_arn() == Some(ROLE)
                && r.action_names() == RESTORE_ACTIONS
                && r.context_entries().iter().any(|c| {
                    c.context_key_name() == Some("kms:GrantIsForAWSResource")
                        && c.context_key_values() == ["true"]
                })
        })
        .then_output(move || {
            SimulatePrincipalPolicyOutput::builder()
                .set_evaluation_results(Some(results.clone()))
                .build()
        });
    mock_client!(aws_sdk_iam, RuleMode::Sequential, [&rule])
}

const ROLE: &str = "arn:aws:iam::123456789012:role/backup-restore";

#[tokio::test]
async fn simulate_restore_splits_allowed_and_denied() {
    use aws_sdk_iam::types::PolicyEvaluationDecisionType as D;
    let iam = simulate_client(vec![
        eval("backup:StartRestoreJob", D::Allowed, &[]),
        eval("kms:CreateGrant", D::ImplicitDeny, &[]),
        eval("kms:Decrypt", D::ExplicitDeny, &[]),
        eval("rds:RestoreDBInstanceFromDBSnapshot", D::Allowed, &[]),
        eval("ec2:RunInstances", D::Allowed, &[]),
    ]);
    let r = simulate_restore(&iam, ROLE, "123456789012").await.unwrap();
    assert!(r.unknown.is_empty());
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

#[tokio::test]
async fn simulate_restore_all_allowed() {
    use aws_sdk_iam::types::PolicyEvaluationDecisionType as D;
    let iam = simulate_client(
        RESTORE_ACTIONS
            .iter()
            .map(|a| eval(a, D::Allowed, &[]))
            .collect(),
    );
    let r = simulate_restore(&iam, ROLE, "123456789012").await.unwrap();
    assert!(r.unknown.is_empty() && r.denied.is_empty());
    assert_eq!(r.allowed.len(), 5);
}

#[tokio::test]
async fn simulate_restore_missing_context_is_unknown_per_action_and_keeps_explicit_deny() {
    use aws_sdk_iam::types::PolicyEvaluationDecisionType as D;
    let iam = simulate_client(vec![
        eval("backup:StartRestoreJob", D::Allowed, &[]),
        eval("kms:CreateGrant", D::ExplicitDeny, &["kms:ViaService"]),
        eval("kms:Decrypt", D::ImplicitDeny, &["kms:ViaService"]),
        eval("ec2:RunInstances", D::ImplicitDeny, &[]),
    ]);
    let r = simulate_restore(&iam, ROLE, "123456789012").await.unwrap();
    assert_eq!(r.allowed, vec!["backup:StartRestoreJob"]);
    assert_eq!(r.denied, vec!["ec2:RunInstances", "kms:CreateGrant"]);
    assert_eq!(r.unknown, vec!["kms:Decrypt"]);
}

#[tokio::test]
async fn simulate_restore_role_outcomes() {
    use aws_sdk_iam::operation::simulate_principal_policy::SimulatePrincipalPolicyError;
    let failing = |code: &'static str| {
        let rule = mock!(aws_sdk_iam::Client::simulate_principal_policy).then_error(move || {
            SimulatePrincipalPolicyError::generic(
                aws_sdk_iam::error::ErrorMetadata::builder()
                    .code(code)
                    .build(),
            )
        });
        (
            mock_client!(aws_sdk_iam, RuleMode::Sequential, [&rule]),
            rule,
        )
    };
    let all_unknown = |r: &opsagent_connectors::SimulationResult| {
        r.unknown == RESTORE_ACTIONS && r.denied.is_empty() && r.allowed.is_empty()
    };
    // Missing role: every action unknown.
    let (iam, _) = failing("NoSuchEntity");
    assert!(all_unknown(
        &simulate_restore(&iam, ROLE, "123456789012").await.unwrap()
    ));
    // Role in another account: unknown without calling IAM.
    let (iam, rule) = failing("AccessDenied");
    assert!(all_unknown(
        &simulate_restore(&iam, ROLE, "999999999999").await.unwrap()
    ));
    assert_eq!(rule.num_calls(), 0);
    // AccessDenied on our own simulate call: our permission gap, an error with its code.
    let err = simulate_restore(&iam, ROLE, "123456789012")
        .await
        .unwrap_err();
    assert!(
        matches!(&err, opsagent_connectors::ConnectorError::Api { code: Some(c), .. } if c == "AccessDenied"),
        "{err:?}"
    );
    let (iam, _) = failing("Throttling");
    assert!(simulate_restore(&iam, ROLE, "123456789012").await.is_err());
}

#[tokio::test]
async fn failed_coverage_read_in_ebs_chunk_is_a_backup_partial_error() {
    use aws_smithy_http_client::test_util::infallible_client_fn;
    use opsagent_connectors::aws::inventory::inventory;
    use opsagent_connectors::Scope;
    let http = infallible_client_fn(|req| {
        let host = req.uri().host().unwrap_or_default().to_owned();
        let path = req.uri().path().to_owned();
        let r = http::Response::builder();
        if host.starts_with("backup.") && path.starts_with("/backup-jobs") {
            return r
                .status(400)
                .header("x-amzn-ErrorType", "ThrottlingException")
                .body(r#"{"message":"slow down"}"#.to_owned())
                .unwrap();
        }
        if host.starts_with("backup.") {
            return r.status(200).body("{}".to_owned()).unwrap();
        }
        r.status(200)
            .body(
                "<DescribeVolumesResponse xmlns=\"http://ec2.amazonaws.com/doc/2016-11-15/\">\
                 <requestId>r-1</requestId><volumeSet><item><volumeId>vol-1</volumeId>\
                 <size>8</size></item></volumeSet></DescribeVolumesResponse>"
                    .to_owned(),
            )
            .unwrap()
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
    let scope = Scope {
        regions: vec!["eu-west-1".into()],
        services: vec!["ebs".into()],
    };
    let r = inventory(&session, "aws", "123456789012", &scope)
        .await
        .unwrap();
    assert_eq!(r.partial_errors.len(), 1, "{:?}", r.partial_errors);
    assert_eq!(r.partial_errors[0].service, "backup");
    assert_eq!(
        r.partial_errors[0].code.as_deref(),
        Some("ThrottlingException")
    );
    assert_eq!(r.resources.len(), 1);
    let a = r.resources[0].attributes.as_object().unwrap();
    assert_eq!(a["service"], "ebs");
    for k in [
        "in_backup_plan",
        "backup_last_job_status",
        "backup_last_job_at",
    ] {
        assert!(!a.contains_key(k), "{k} present");
    }
}
