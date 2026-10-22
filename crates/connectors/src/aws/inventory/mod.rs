//! Inventory: raw AWS responses mapped into `Resource`. Attribute keys are the contract checks
//! read; they match `fixtures/accounts/noisy.json`. One file per service family.

mod acm;
mod backup;
mod ec2;
mod gpu;
mod iam;
mod logging;
mod logs;
mod rds;
mod s3;

pub use acm::certificates;
pub use backup::{backups, mark_backup_coverage};
pub use ec2::{ec2_addresses, ec2_instances, ec2_volumes, load_balancers, security_groups};
pub use gpu::{gpu_utilisation, training_jobs};
pub use iam::{credential_report, credential_report_users, iam_users};
pub use logging::{cloudtrails, guardduty};
pub use logs::log_groups;
pub use rds::{rds_instances, rds_snapshots};
pub use s3::s3_buckets;

use super::client::provider_err;
use crate::{ConnectorError, InventoryResult, Result, Scope, ServiceError};
use aws_config::{Region, SdkConfig};
use chrono::{DateTime, SecondsFormat, Utc};
use opsagent_core::resource::{Provider, Resource, ResourceKind};
use serde_json::Value;
use std::collections::BTreeMap;
use std::future::Future;

pub const INVENTORY_ACTIONS: &[&str] = &[
    "ec2:DescribeRegions",
    "ec2:DescribeInstances",
    "ec2:DescribeVolumes",
    "ec2:DescribeAddresses",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeNetworkInterfaces",
    "elasticloadbalancing:DescribeLoadBalancers",
    "rds:DescribeDBInstances",
    "rds:DescribeDBSnapshots",
    "rds:DescribeDBSnapshotAttributes",
    "s3:ListAllMyBuckets",
    "s3:GetBucketLocation",
    "s3:GetBucketPublicAccessBlock",
    "s3:GetBucketPolicyStatus",
    "iam:GenerateCredentialReport",
    "iam:GetCredentialReport",
    "iam:ListAttachedUserPolicies",
    "cloudtrail:DescribeTrails",
    "cloudtrail:GetTrailStatus",
    "guardduty:ListDetectors",
    "guardduty:GetDetector",
    "backup:ListBackupPlans",
    "backup:GetBackupPlan",
    "backup:ListBackupJobs",
    "backup:ListBackupVaults",
    "acm:ListCertificates",
    "acm:DescribeCertificate",
    "logs:DescribeLogGroups",
    "cloudwatch:GetMetricData",
    "cloudwatch:ListMetrics",
    "sagemaker:ListTrainingJobs",
];

/// Account and region a call is made in; builds ARNs and `Resource`s.
#[derive(Debug, Clone, Copy)]
pub struct Target<'a> {
    pub partition: &'a str,
    pub account: &'a str,
    pub region: &'a str,
}

impl Target<'_> {
    fn arn(&self, service: &str, res: &str) -> String {
        format!(
            "arn:{}:{service}:{}:{}:{res}",
            self.partition, self.region, self.account
        )
    }

    fn resource(
        &self,
        kind: ResourceKind,
        identity: String,
        name: &str,
        tags: BTreeMap<String, String>,
        attributes: Value,
    ) -> Resource {
        Resource {
            provider: Provider::Aws,
            account: self.account.to_owned(),
            region: self.region.to_owned(),
            kind,
            identity,
            name: name.to_owned(),
            tags,
            attributes,
            observed_at: Utc::now(),
        }
    }
}

/// Removes `environment`, `Environment` and `secrets` at any depth. Run on every response that
/// can carry env or secrets (`ecs:DescribeTaskDefinition`, `lambda:GetFunctionConfiguration`)
/// before it is stored, logged or passed to a check.
pub fn strip_env(v: &mut Value) {
    match v {
        Value::Object(m) => {
            m.retain(|k, _| !matches!(k.as_str(), "environment" | "Environment" | "secrets"));
            m.values_mut().for_each(strip_env);
        }
        Value::Array(xs) => xs.iter_mut().for_each(strip_env),
        _ => {}
    }
}

fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn rfc3339_aws(t: &aws_sdk_backup::primitives::DateTime) -> Option<String> {
    DateTime::from_timestamp(t.secs(), t.subsec_nanos()).map(rfc3339)
}

fn name_or<'a>(tags: &'a BTreeMap<String, String>, id: &'a str) -> &'a str {
    tags.get("Name").map_or(id, String::as_str)
}

fn service_error(service: &str, region: &str, e: &ConnectorError) -> ServiceError {
    ServiceError {
        service: service.into(),
        region: region.into(),
        code: match e {
            ConnectorError::Api { code, .. } => code.clone(),
            _ => None,
        },
        message: e.to_string(),
    }
}

/// Codes meaning the credentials themselves are bad (expired, unknown, or badly signed).
const TOKEN_CODES: &[&str] = &[
    "ExpiredToken",
    "ExpiredTokenException",
    "InvalidClientTokenId",
    "UnrecognizedClientException",
    "AuthFailure",
    "RequestExpired",
    "InvalidAccessKeyId",
    "InvalidToken",
    "InvalidSignatureException",
];
const DENIED_CODES: &[&str] = &["AccessDenied", "AccessDeniedException"];

/// Outcome of one service call during inventory: `Err(code)` on failure.
pub type CallOutcome = (String, std::result::Result<(), Option<String>>);

/// The session is unusable when some region fails every call with a token error, or when
/// every call everywhere fails with a token or access-denied error. AccessDenied confined to
/// some regions (an SCP) stays a partial error.
pub fn auth_failure(calls: &[CallOutcome]) -> Option<String> {
    let failed_with = |r: &std::result::Result<(), Option<String>>, set: &[&str]| matches!(r, Err(Some(c)) if set.contains(&c.as_str()));
    let regions: std::collections::BTreeSet<&str> = calls.iter().map(|(r, _)| r.as_str()).collect();
    for region in regions {
        let mut cs = calls.iter().filter(|(r, _)| r == region).peekable();
        if cs.peek().is_some() && cs.all(|(_, o)| failed_with(o, TOKEN_CODES)) {
            return Some(format!(
                "every call in {region} failed with an invalid or expired token"
            ));
        }
    }
    let any = [TOKEN_CODES, DENIED_CODES].concat();
    (!calls.is_empty() && calls.iter().all(|(_, o)| failed_with(o, &any)))
        .then(|| "every call was denied".to_owned())
}

async fn gate<F: Future<Output = Result<Vec<Resource>>>>(
    on: bool,
    f: F,
) -> Option<Result<Vec<Resource>>> {
    if on {
        Some(f.await)
    } else {
        None
    }
}

/// Every region the session can see, or the scoped ones. A denied or invalid session fails the
/// whole call with `ConnectorError::Auth`.
async fn regions(session: &SdkConfig, scope: &Scope) -> Result<Vec<String>> {
    if !scope.regions.is_empty() {
        return Ok(scope.regions.clone());
    }
    let out = aws_sdk_ec2::Client::new(session)
        .describe_regions()
        .send()
        .await
        .map_err(|e| match provider_err(e) {
            ConnectorError::Api { code: Some(c), .. }
                if TOKEN_CODES.contains(&c.as_str()) || DENIED_CODES.contains(&c.as_str()) =>
            {
                ConnectorError::Auth(format!("DescribeRegions failed with {c}"))
            }
            e => e,
        })?;
    Ok(out
        .regions()
        .iter()
        .filter_map(|r| r.region_name().map(str::to_owned))
        .collect())
}

/// Collects per-service outcomes: resources, partial errors, and the call log `auth_failure` reads.
#[derive(Default)]
struct Collect {
    result: InventoryResult,
    calls: Vec<CallOutcome>,
}

impl Collect {
    fn record(&mut self, service: &str, region: &str, r: Option<Result<Vec<Resource>>>) {
        match r {
            Some(Ok(v)) => {
                self.calls.push((region.into(), Ok(())));
                self.result.resources.extend(v);
            }
            Some(Err(e)) => {
                let se = service_error(service, region, &e);
                self.calls.push((region.into(), Err(se.code.clone())));
                self.result.partial_errors.push(se);
            }
            None => {}
        }
    }
}

/// The regional services in one region, concurrently.
async fn regional(
    session: &SdkConfig,
    t: &Target<'_>,
    want: &impl Fn(&str) -> bool,
    out: &mut Collect,
) {
    let cfg = session
        .to_builder()
        .region(Region::new(t.region.to_owned()))
        .build();
    let ec2 = aws_sdk_ec2::Client::new(&cfg);
    let elb = aws_sdk_elasticloadbalancingv2::Client::new(&cfg);
    let rds = aws_sdk_rds::Client::new(&cfg);
    let ct = aws_sdk_cloudtrail::Client::new(&cfg);
    let gd = aws_sdk_guardduty::Client::new(&cfg);
    let (mut a, b, c, d, e, mut f, g, h, i) = tokio::join!(
        gate(want("ec2"), ec2_instances(&ec2, t)),
        gate(want("ebs"), ec2_volumes(&ec2, t)),
        gate(want("eip"), ec2_addresses(&ec2, t)),
        gate(want("sg"), security_groups(&ec2, t)),
        gate(want("elb"), load_balancers(&elb, t)),
        gate(want("rds"), rds_instances(&rds, t)),
        gate(want("rds"), rds_snapshots(&rds, t)),
        gate(want("cloudtrail"), cloudtrails(&ct, t)),
        gate(want("guardduty"), guardduty(&gd, t)),
    );
    protection_and_ml(&cfg, t, want, out, &mut a, &mut f).await;
    for (svc, r) in [
        ("ec2", a),
        ("ebs", b),
        ("eip", c),
        ("sg", d),
        ("elb", e),
        ("rds", f),
        ("rds", g),
        ("cloudtrail", h),
        ("guardduty", i),
    ] {
        out.record(svc, t.region, r);
    }
}

/// Backups, certificates, log groups and training jobs; GPU utilisation onto `ec2`
/// instances and backup coverage onto `rds` instances. Backups are read for an `rds`-only
/// scope too (coverage needs them) but only returned when `backup` is wanted.
async fn protection_and_ml(
    cfg: &SdkConfig,
    t: &Target<'_>,
    want: &impl Fn(&str) -> bool,
    out: &mut Collect,
    ec2: &mut Option<Result<Vec<Resource>>>,
    rds: &mut Option<Result<Vec<Resource>>>,
) {
    let now = Utc::now();
    let bk = aws_sdk_backup::Client::new(cfg);
    let acm = aws_sdk_acm::Client::new(cfg);
    let lg = aws_sdk_cloudwatchlogs::Client::new(cfg);
    let sm = aws_sdk_sagemaker::Client::new(cfg);
    let cw = aws_sdk_cloudwatch::Client::new(cfg);
    let mut cert_errs = vec![];
    let (bkp, certs, groups, jobs) = tokio::join!(
        gate(want("backup") || want("rds"), backups(&bk, t, now)),
        gate(want("acm"), certificates(&acm, t, &mut cert_errs)),
        gate(want("logs"), log_groups(&lg, t)),
        gate(want("sagemaker"), training_jobs(&sm, t)),
    );
    if let (Some(Ok(dbs)), Some(Ok(plans))) = (rds.as_mut(), bkp.as_ref()) {
        mark_backup_coverage(dbs, plans);
    }
    if let Some(Ok(v)) = ec2.as_mut() {
        if let Some(e) = gpu_utilisation(&cw, v, now).await {
            out.record("cloudwatch", t.region, Some(Err(e)));
        }
    }
    let bkp = match bkp {
        Some(Ok(_)) if !want("backup") => None,
        r => r,
    };
    for (svc, r) in [
        ("backup", bkp),
        ("acm", certs),
        ("logs", groups),
        ("sagemaker", jobs),
    ] {
        out.record(svc, t.region, r);
    }
    out.result.partial_errors.extend(cert_errs);
}

/// Full inventory for a session. Per-service failures land in `partial_errors`; see
/// `auth_failure` for when the whole call fails with `ConnectorError::Auth`.
pub async fn inventory(
    session: &SdkConfig,
    partition: &str,
    account: &str,
    scope: &Scope,
) -> Result<InventoryResult> {
    let want = |s: &str| scope.services.is_empty() || scope.services.iter().any(|x| x == s);
    let mut out = Collect::default();
    for region in &regions(session, scope).await? {
        let t = Target {
            partition,
            account,
            region,
        };
        regional(session, &t, &want, &mut out).await;
    }
    let global = Target {
        partition,
        account,
        region: "global",
    };
    let iam = aws_sdk_iam::Client::new(session);
    let users = gate(want("iam"), iam_users(&iam, &global)).await;
    out.record("iam", "global", users);
    if want("s3") {
        let mut errs = vec![];
        let r = s3_buckets(session, &global, &mut errs).await;
        out.record("s3", "global", Some(r));
        out.result.partial_errors.extend(errs);
    }
    if let Some(why) = auth_failure(&out.calls) {
        return Err(ConnectorError::Auth(why));
    }
    Ok(out.result)
}
