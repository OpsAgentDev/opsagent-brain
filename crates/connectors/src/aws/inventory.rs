//! Inventory: raw AWS responses mapped into `Resource`. Attribute keys are the contract checks
//! read; they match `fixtures/accounts/noisy.json`.

use super::client::provider_err;
use crate::{ConnectorError, InventoryResult, Result, Scope, ServiceError};
use aws_config::{Region, SdkConfig};
use aws_sdk_s3::error::ProvideErrorMetadata;
use chrono::{DateTime, NaiveDate, Utc};
use opsagent_core::resource::{resource_identity, Provider, Resource, ResourceKind};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::future::Future;

pub(crate) const INVENTORY_ACTIONS: &[&str] = &[
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

fn ec2_tags(tags: &[aws_sdk_ec2::types::Tag]) -> BTreeMap<String, String> {
    tags.iter()
        .filter_map(|t| {
            Some((
                t.key()?.to_owned(),
                t.value().unwrap_or_default().to_owned(),
            ))
        })
        .collect()
}

fn name_or<'a>(tags: &'a BTreeMap<String, String>, id: &'a str) -> &'a str {
    tags.get("Name").map_or(id, String::as_str)
}

fn accelerated(instance_type: &str) -> bool {
    let family = instance_type.split('.').next().unwrap_or_default();
    ["p", "g", "inf", "trn", "dl"]
        .iter()
        .any(|f| family.starts_with(f))
}

pub async fn ec2_instances(ec2: &aws_sdk_ec2::Client, t: &Target<'_>) -> Result<Vec<Resource>> {
    let mut out = vec![];
    let mut pages = ec2.describe_instances().into_paginator().send();
    while let Some(page) = pages.next().await {
        let page = page.map_err(provider_err)?;
        for i in page.reservations().iter().flat_map(|r| r.instances()) {
            let id = i.instance_id().unwrap_or_default();
            let ty = i.instance_type().map(|x| x.as_str()).unwrap_or_default();
            let tags = ec2_tags(i.tags());
            let attrs = json!({
                "service": "ec2",
                "state": i.state().and_then(|s| s.name()).map(|s| s.as_str()),
                "instance_type": ty,
                "accelerated": accelerated(ty),
                "cpu_avg_7d": null,
                "monthly_cost_usd": null,
            });
            let arn = t.arn("ec2", &format!("instance/{id}"));
            out.push(t.resource(
                ResourceKind::Compute,
                arn,
                name_or(&tags, id),
                tags.clone(),
                attrs,
            ));
        }
    }
    Ok(out)
}

pub async fn ec2_volumes(ec2: &aws_sdk_ec2::Client, t: &Target<'_>) -> Result<Vec<Resource>> {
    let mut out = vec![];
    let mut pages = ec2.describe_volumes().into_paginator().send();
    while let Some(page) = pages.next().await {
        for v in page.map_err(provider_err)?.volumes() {
            let id = v.volume_id().unwrap_or_default();
            let tags = ec2_tags(v.tags());
            let attrs = json!({
                "service": "ebs",
                "attached": !v.attachments().is_empty(),
                "size_gb": v.size(),
                "monthly_cost_usd": null,
            });
            let arn = t.arn("ec2", &format!("volume/{id}"));
            out.push(t.resource(
                ResourceKind::Storage,
                arn,
                name_or(&tags, id),
                tags.clone(),
                attrs,
            ));
        }
    }
    Ok(out)
}

pub async fn ec2_addresses(ec2: &aws_sdk_ec2::Client, t: &Target<'_>) -> Result<Vec<Resource>> {
    let out = ec2
        .describe_addresses()
        .send()
        .await
        .map_err(provider_err)?;
    Ok(out
        .addresses()
        .iter()
        .map(|a| {
            let id = a.allocation_id().or(a.public_ip()).unwrap_or_default();
            let tags = ec2_tags(a.tags());
            let attrs = json!({"service": "eip", "associated": a.association_id().is_some()});
            let arn = t.arn("ec2", &format!("elastic-ip/{id}"));
            t.resource(
                ResourceKind::Network,
                arn,
                name_or(&tags, id),
                tags.clone(),
                attrs,
            )
        })
        .collect())
}

// shortcut: ranges report their endpoints plus well-known service ports inside them, not every
// port; upgrade to a range representation if a check needs exact coverage.
const NOTABLE_PORTS: &[u16] = &[
    22, 80, 443, 1433, 2375, 3306, 3389, 5432, 5601, 6379, 8080, 9200, 11211, 27017,
];

fn open_world_ports(perms: &[aws_sdk_ec2::types::IpPermission]) -> Vec<u16> {
    let mut ports = vec![];
    for p in perms {
        let world = p
            .ip_ranges()
            .iter()
            .any(|r| r.cidr_ip() == Some("0.0.0.0/0"))
            || p.ipv6_ranges()
                .iter()
                .any(|r| r.cidr_ipv6() == Some("::/0"));
        if !world {
            continue;
        }
        let (from, to) = match p.ip_protocol() {
            Some("-1") => (0, 65535),
            _ => (
                p.from_port().unwrap_or(0).clamp(0, 65535) as u16,
                p.to_port().unwrap_or(65535).clamp(0, 65535) as u16,
            ),
        };
        ports.extend([from, to]);
        ports.extend(NOTABLE_PORTS.iter().filter(|x| (from..=to).contains(*x)));
    }
    ports.sort_unstable();
    ports.dedup();
    ports
}

pub async fn security_groups(ec2: &aws_sdk_ec2::Client, t: &Target<'_>) -> Result<Vec<Resource>> {
    // Group id -> "lb" | "instance", from the ENIs that carry it.
    let mut attached: HashMap<String, &str> = HashMap::new();
    let mut enis = ec2.describe_network_interfaces().into_paginator().send();
    while let Some(page) = enis.next().await {
        for n in page.map_err(provider_err)?.network_interfaces() {
            let to = if n.description().unwrap_or_default().contains("ELB") {
                "lb"
            } else if n.attachment().and_then(|a| a.instance_id()).is_some() {
                "instance"
            } else {
                continue;
            };
            for g in n.groups().iter().filter_map(|g| g.group_id()) {
                let e = attached.entry(g.to_owned()).or_insert(to);
                if to == "lb" {
                    *e = "lb";
                }
            }
        }
    }
    let mut out = vec![];
    let mut pages = ec2.describe_security_groups().into_paginator().send();
    while let Some(page) = pages.next().await {
        for g in page.map_err(provider_err)?.security_groups() {
            let id = g.group_id().unwrap_or_default();
            let tags = ec2_tags(g.tags());
            let attrs = json!({
                "service": "sg",
                "open_world_ports": open_world_ports(g.ip_permissions()),
                "attached_to": attached.get(id).copied().unwrap_or("none"),
            });
            let arn = t.arn("ec2", &format!("security-group/{id}"));
            let name = g.group_name().unwrap_or(id);
            out.push(t.resource(ResourceKind::Network, arn, name, tags, attrs));
        }
    }
    Ok(out)
}

pub async fn load_balancers(
    elb: &aws_sdk_elasticloadbalancingv2::Client,
    t: &Target<'_>,
) -> Result<Vec<Resource>> {
    let mut out = vec![];
    let mut pages = elb.describe_load_balancers().into_paginator().send();
    while let Some(page) = pages.next().await {
        for lb in page.map_err(provider_err)?.load_balancers() {
            let attrs = json!({"service": "elb", "request_count_7d": null});
            out.push(t.resource(
                ResourceKind::Network,
                lb.load_balancer_arn().unwrap_or_default().to_owned(),
                lb.load_balancer_name().unwrap_or_default(),
                BTreeMap::new(),
                attrs,
            ));
        }
    }
    Ok(out)
}

pub async fn rds_instances(rds: &aws_sdk_rds::Client, t: &Target<'_>) -> Result<Vec<Resource>> {
    let mut out = vec![];
    let mut pages = rds.describe_db_instances().into_paginator().send();
    while let Some(page) = pages.next().await {
        for db in page.map_err(provider_err)?.db_instances() {
            let attrs = json!({
                "service": "rds",
                "publicly_accessible": db.publicly_accessible(),
                "backup_retention_days": db.backup_retention_period(),
            });
            let tags = db
                .tag_list()
                .iter()
                .filter_map(|x| {
                    Some((
                        x.key()?.to_owned(),
                        x.value().unwrap_or_default().to_owned(),
                    ))
                })
                .collect();
            out.push(t.resource(
                ResourceKind::Database,
                db.db_instance_arn().unwrap_or_default().to_owned(),
                db.db_instance_identifier().unwrap_or_default(),
                tags,
                attrs,
            ));
        }
    }
    Ok(out)
}

/// Manual snapshots (only those can be shared); `public` when `restore` includes `all`.
pub async fn rds_snapshots(rds: &aws_sdk_rds::Client, t: &Target<'_>) -> Result<Vec<Resource>> {
    let mut out = vec![];
    let mut pages = rds
        .describe_db_snapshots()
        .snapshot_type("manual")
        .into_paginator()
        .send();
    while let Some(page) = pages.next().await {
        for s in page.map_err(provider_err)?.db_snapshots() {
            let id = s.db_snapshot_identifier().unwrap_or_default();
            let attrs = rds
                .describe_db_snapshot_attributes()
                .db_snapshot_identifier(id)
                .send()
                .await
                .map_err(provider_err)?;
            let public = attrs
                .db_snapshot_attributes_result()
                .map(|r| r.db_snapshot_attributes())
                .unwrap_or_default()
                .iter()
                .any(|a| {
                    a.attribute_name() == Some("restore")
                        && a.attribute_values().iter().any(|v| v == "all")
                });
            out.push(t.resource(
                ResourceKind::Database,
                s.db_snapshot_arn().unwrap_or_default().to_owned(),
                id,
                BTreeMap::new(),
                json!({"service": "rds", "snapshot": true, "public": public}),
            ));
        }
    }
    Ok(out)
}

pub async fn cloudtrails(ct: &aws_sdk_cloudtrail::Client, t: &Target<'_>) -> Result<Vec<Resource>> {
    // Shadow trails excluded so a multi-region trail is reported once, in its home region.
    let trails = ct
        .describe_trails()
        .include_shadow_trails(false)
        .send()
        .await
        .map_err(provider_err)?;
    let mut out = vec![];
    for tr in trails.trail_list() {
        let arn = tr.trail_arn().unwrap_or_default();
        let status = ct
            .get_trail_status()
            .name(arn)
            .send()
            .await
            .map_err(provider_err)?;
        out.push(t.resource(
            ResourceKind::Log,
            arn.to_owned(),
            tr.name().unwrap_or_default(),
            BTreeMap::new(),
            json!({"service": "cloudtrail", "logging": status.is_logging().unwrap_or(false)}),
        ));
    }
    Ok(out)
}

/// One resource per region, present even when no detector exists (`enabled: false`).
pub async fn guardduty(gd: &aws_sdk_guardduty::Client, t: &Target<'_>) -> Result<Vec<Resource>> {
    let ids = gd.list_detectors().send().await.map_err(provider_err)?;
    let (identity, enabled) = match ids.detector_ids().first() {
        Some(id) => {
            let d = gd
                .get_detector()
                .detector_id(id)
                .send()
                .await
                .map_err(provider_err)?;
            let on = d.status() == Some(&aws_sdk_guardduty::types::DetectorStatus::Enabled);
            (t.arn("guardduty", &format!("detector/{id}")), on)
        }
        None => (
            resource_identity(None, ResourceKind::Log, "guardduty", t.region),
            false,
        ),
    };
    Ok(vec![t.resource(
        ResourceKind::Log,
        identity,
        "guardduty",
        BTreeMap::new(),
        json!({"service": "guardduty", "enabled": enabled}),
    )])
}

/// Global. Per-bucket failures are recorded and the bucket skipped.
pub async fn s3_buckets(
    session: &SdkConfig,
    t: &Target<'_>,
    errors: &mut Vec<ServiceError>,
) -> Result<Vec<Resource>> {
    let s3 = aws_sdk_s3::Client::new(session);
    let mut clients: HashMap<String, aws_sdk_s3::Client> = HashMap::new();
    let mut out = vec![];
    let mut pages = s3.list_buckets().into_paginator().send();
    while let Some(page) = pages.next().await {
        for b in page.map_err(provider_err)?.buckets() {
            let name = b.name().unwrap_or_default();
            let res: Result<Resource> = async {
                let region = match b.bucket_region() {
                    Some(r) => r.to_owned(),
                    None => {
                        let loc = s3
                            .get_bucket_location()
                            .bucket(name)
                            .send()
                            .await
                            .map_err(provider_err)?;
                        match loc.location_constraint().map(|c| c.as_str()) {
                            None | Some("") => "us-east-1".to_owned(),
                            Some("EU") => "eu-west-1".to_owned(),
                            Some(r) => r.to_owned(),
                        }
                    }
                };
                let c = clients.entry(region.clone()).or_insert_with(|| {
                    aws_sdk_s3::Client::new(
                        &session.to_builder().region(Region::new(region.clone())).build(),
                    )
                });
                let block = match c.get_public_access_block().bucket(name).send().await {
                    Ok(o) => o.public_access_block_configuration().is_some_and(|p| {
                        p.block_public_acls() == Some(true)
                            && p.ignore_public_acls() == Some(true)
                            && p.block_public_policy() == Some(true)
                            && p.restrict_public_buckets() == Some(true)
                    }),
                    Err(e) if e.code() == Some("NoSuchPublicAccessBlockConfiguration") => false,
                    Err(e) => return Err(provider_err(e)),
                };
                let public = match c.get_bucket_policy_status().bucket(name).send().await {
                    Ok(o) => o.policy_status().and_then(|p| p.is_public()).unwrap_or(false),
                    Err(e) if e.code() == Some("NoSuchBucketPolicy") => false,
                    Err(e) => return Err(provider_err(e)),
                };
                // Without s3:GetBucketPolicy the public prefix is unknown; "" means "some or all".
                let prefix = public.then_some("");
                let bt = Target {
                    region: &region,
                    ..*t
                };
                Ok(bt.resource(
                    ResourceKind::Storage,
                    format!("arn:{}:s3:::{name}", t.partition),
                    name,
                    BTreeMap::new(),
                    json!({"service": "s3", "block_public_access": block, "public_policy_prefix": prefix}),
                ))
            }
            .await;
            match res {
                Ok(r) => out.push(r),
                Err(e) => errors.push(service_error("s3", &format!("bucket:{name}"), &e)),
            }
        }
    }
    Ok(out)
}

fn days_since(ts: &str, now: DateTime<Utc>) -> Option<i64> {
    // Report timestamps are ISO 8601; "N/A" and "no_information" fail the parse.
    let d = NaiveDate::parse_from_str(ts.get(..10)?, "%Y-%m-%d").ok()?;
    Some((now.date_naive() - d).num_days())
}

/// Splits one CSV record; handles quoted fields and doubled quotes.
fn csv_fields(line: &str) -> Vec<String> {
    let (mut out, mut cur, mut quoted) = (vec![], String::new(), false);
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => out.push(std::mem::take(&mut cur)),
            c => cur.push(c),
        }
    }
    out.push(cur);
    out
}

/// Parses the IAM credential report CSV into identity resources. The `<root_account>` row
/// becomes a `root: true` resource; `admin` for users comes from `admins`.
pub fn credential_report_users(
    csv: &str,
    admins: &dyn Fn(&str) -> bool,
    t: &Target<'_>,
    now: DateTime<Utc>,
) -> Vec<Resource> {
    let mut lines = csv.lines();
    let header = csv_fields(lines.next().unwrap_or_default());
    let col = |row: &[String], name: &str| -> String {
        header
            .iter()
            .position(|h| h == name)
            .and_then(|i| row.get(i))
            .cloned()
            .unwrap_or_default()
    };
    let mut out = vec![];
    for line in lines.filter(|l| !l.is_empty()) {
        let row = csv_fields(line);
        let user = col(&row, "user");
        if user.is_empty() {
            continue;
        }
        let active: Vec<&str> = ["access_key_1", "access_key_2"]
            .into_iter()
            .filter(|k| col(&row, &format!("{k}_active")) == "true")
            .collect();
        let mfa = col(&row, "mfa_active") == "true";
        if user == "<root_account>" {
            let attrs = json!({
                "service": "iam",
                "root": true,
                "mfa": mfa,
                "access_keys_active": active.len() as u8,
                "console_last_used_days": days_since(&col(&row, "password_last_used"), now),
            });
            out.push(t.resource(
                ResourceKind::Identity,
                col(&row, "arn"),
                "root",
                BTreeMap::new(),
                attrs,
            ));
            continue;
        }
        let (mut age, mut used): (Option<i64>, Option<i64>) = (None, None);
        for k in active {
            let rotated = days_since(&col(&row, &format!("{k}_last_rotated")), now);
            // A never-used key counts as unused since it was created.
            let last = days_since(&col(&row, &format!("{k}_last_used_date")), now).or(rotated);
            age = age.max(rotated);
            used = match (used, last) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
        }
        let attrs = json!({
            "service": "iam",
            "key_age_days": age,
            "key_last_used_days": used,
            "mfa": mfa,
            "console": col(&row, "password_enabled") == "true",
            "admin": admins(&user),
        });
        out.push(t.resource(
            ResourceKind::Identity,
            col(&row, "arn"),
            &user,
            BTreeMap::new(),
            attrs,
        ));
    }
    out
}

/// Generates and fetches the credential report: retries while it is in progress, regenerates
/// when it has expired, gives up after `max_wait`.
pub async fn credential_report(
    iam: &aws_sdk_iam::Client,
    poll: std::time::Duration,
    max_wait: std::time::Duration,
) -> Result<String> {
    let deadline = tokio::time::Instant::now() + max_wait;
    let mut generate = true;
    loop {
        if generate {
            iam.generate_credential_report()
                .send()
                .await
                .map_err(provider_err)?;
            generate = false;
        }
        match iam.get_credential_report().send().await {
            Ok(r) => {
                return Ok(r
                    .content()
                    .map(|b| String::from_utf8_lossy(b.as_ref()).into_owned())
                    .unwrap_or_default())
            }
            Err(e) => match e.as_service_error() {
                Some(se)
                    if se.is_credential_report_not_ready_exception()
                        || se.is_credential_report_not_present_exception() => {}
                Some(se) if se.is_credential_report_expired_exception() => generate = true,
                _ => return Err(provider_err(e)),
            },
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(ConnectorError::Provider(format!(
                "credential report not ready after {}s",
                max_wait.as_secs()
            )));
        }
        tokio::time::sleep(poll).await;
    }
}

pub async fn iam_users(iam: &aws_sdk_iam::Client, t: &Target<'_>) -> Result<Vec<Resource>> {
    use std::time::Duration;
    let csv = credential_report(iam, Duration::from_secs(2), Duration::from_secs(120)).await?;
    let users: Vec<String> = credential_report_users(&csv, &|_| false, t, Utc::now())
        .into_iter()
        .filter(|r| r.attributes.get("root").is_none())
        .map(|r| r.name)
        .collect();
    let mut admins = std::collections::HashSet::new();
    for u in &users {
        let mut pages = iam
            .list_attached_user_policies()
            .user_name(u)
            .into_paginator()
            .items()
            .send();
        while let Some(p) = pages.next().await {
            if p.map_err(provider_err)?
                .policy_arn()
                .unwrap_or_default()
                .ends_with(":policy/AdministratorAccess")
            {
                admins.insert(u.clone());
            }
        }
    }
    Ok(credential_report_users(
        &csv,
        &|u| admins.contains(u),
        t,
        Utc::now(),
    ))
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

const TOKEN_CODES: &[&str] = &[
    "ExpiredToken",
    "InvalidClientTokenId",
    "UnrecognizedClientException",
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

/// Full inventory for a session. Per-service failures land in `partial_errors`; see
/// `auth_failure` for when the whole call fails with `ConnectorError::Auth`.
pub async fn inventory(
    session: &SdkConfig,
    partition: &str,
    account: &str,
    scope: &Scope,
) -> Result<InventoryResult> {
    let want = |s: &str| scope.services.is_empty() || scope.services.iter().any(|x| x == s);
    let regions = if scope.regions.is_empty() {
        let out = aws_sdk_ec2::Client::new(session)
            .describe_regions()
            .send()
            .await
            .map_err(|e| {
                let e = provider_err(e);
                match &e {
                    ConnectorError::Api { code: Some(c), .. }
                        if TOKEN_CODES.contains(&c.as_str())
                            || DENIED_CODES.contains(&c.as_str()) =>
                    {
                        ConnectorError::Auth(e.to_string())
                    }
                    _ => e,
                }
            })?;
        out.regions()
            .iter()
            .filter_map(|r| r.region_name().map(str::to_owned))
            .collect()
    } else {
        scope.regions.clone()
    };
    let mut result = InventoryResult::default();
    let mut calls: Vec<CallOutcome> = vec![];
    let mut record = |service: &str, region: &str, r: Option<Result<Vec<Resource>>>| match r {
        Some(Ok(v)) => {
            calls.push((region.into(), Ok(())));
            result.resources.extend(v);
        }
        Some(Err(e)) => {
            let se = service_error(service, region, &e);
            calls.push((region.into(), Err(se.code.clone())));
            result.partial_errors.push(se);
        }
        None => {}
    };
    for region in &regions {
        let cfg = session
            .to_builder()
            .region(Region::new(region.clone()))
            .build();
        let t = Target {
            partition,
            account,
            region,
        };
        let ec2 = aws_sdk_ec2::Client::new(&cfg);
        let elb = aws_sdk_elasticloadbalancingv2::Client::new(&cfg);
        let rds = aws_sdk_rds::Client::new(&cfg);
        let ct = aws_sdk_cloudtrail::Client::new(&cfg);
        let gd = aws_sdk_guardduty::Client::new(&cfg);
        let (a, b, c, d, e, f, g, h, i) = tokio::join!(
            gate(want("ec2"), ec2_instances(&ec2, &t)),
            gate(want("ebs"), ec2_volumes(&ec2, &t)),
            gate(want("eip"), ec2_addresses(&ec2, &t)),
            gate(want("sg"), security_groups(&ec2, &t)),
            gate(want("elb"), load_balancers(&elb, &t)),
            gate(want("rds"), rds_instances(&rds, &t)),
            gate(want("rds"), rds_snapshots(&rds, &t)),
            gate(want("cloudtrail"), cloudtrails(&ct, &t)),
            gate(want("guardduty"), guardduty(&gd, &t)),
        );
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
            record(svc, region, r);
        }
    }
    let global = Target {
        partition,
        account,
        region: "global",
    };
    let iam = aws_sdk_iam::Client::new(session);
    record(
        "iam",
        "global",
        gate(want("iam"), iam_users(&iam, &global)).await,
    );
    if want("s3") {
        let mut errs = vec![];
        let r = s3_buckets(session, &global, &mut errs).await;
        record("s3", "global", Some(r));
        result.partial_errors.extend(errs);
    }
    if let Some(why) = auth_failure(&calls) {
        return Err(ConnectorError::Auth(why));
    }
    Ok(result)
}
