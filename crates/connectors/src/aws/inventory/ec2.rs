//! EC2 family: instances, volumes, Elastic IPs, security groups, load balancers.
use super::{name_or, Target};
use crate::aws::client::provider_err;
use crate::Result;
use opsagent_core::resource::{Resource, ResourceKind};
use serde_json::json;
use std::collections::BTreeMap;
use std::collections::HashMap;

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
