//! Seven-day usage for the cost check, from CloudWatch `GetMetricData`: CPU of running EC2
//! instances and traffic of load balancers. One batch per service chunk (500 queries a call),
//! never one call per resource. A resource whose metric cannot be trusted keeps `null`, so a
//! rule on it stays silent: missing data is never read as 0.
use crate::aws::client::provider_err;
use crate::aws::metrics::instance_from_arn;
use crate::{ConnectorError, Result};
use aws_sdk_cloudwatch::primitives::DateTime as AwsTime;
use aws_sdk_cloudwatch::types::{Dimension, Metric, MetricDataQuery, MetricStat, StatusCode};
use chrono::{DateTime, Duration, Utc};
use opsagent_core::resource::Resource;
use serde_json::json;
use std::collections::HashMap;

/// GetMetricData takes at most 500 queries a call.
const BATCH: usize = 500;
const PERIOD_S: i32 = 3600;
/// An instance that ran under 6 of the 7 days has not been "idle for a week".
const MIN_CPU_POINTS: usize = 6 * 24;

/// One query's points; `complete` only when CloudWatch said so for the last page it sent.
#[derive(Default)]
struct Series {
    values: Vec<f64>,
    complete: bool,
}

struct Want {
    id: String,
    namespace: &'static str,
    metric: &'static str,
    stat: &'static str,
    dimension: (&'static str, String),
}

impl Want {
    /// Query `m<index>`; the caller looks the answer up by the same index.
    fn new(
        index: usize,
        namespace: &'static str,
        metric: &'static str,
        stat: &'static str,
        dimension: (&'static str, &str),
    ) -> Self {
        Self {
            id: format!("m{index}"),
            namespace,
            metric,
            stat,
            dimension: (dimension.0, dimension.1.to_owned()),
        }
    }

    fn query(&self) -> MetricDataQuery {
        let (key, value) = &self.dimension;
        let metric = Metric::builder()
            .namespace(self.namespace)
            .metric_name(self.metric)
            .dimensions(Dimension::builder().name(*key).value(value).build())
            .build();
        MetricDataQuery::builder()
            .id(&self.id)
            .metric_stat(
                MetricStat::builder()
                    .metric(metric)
                    .period(PERIOD_S)
                    .stat(self.stat)
                    .build(),
            )
            .return_data(true)
            .build()
    }
}

/// Hourly points of the 7 days ending `now`, by query id.
async fn read(
    cw: &aws_sdk_cloudwatch::Client,
    wants: &[Want],
    now: DateTime<Utc>,
) -> Result<HashMap<String, Series>> {
    let mut got: HashMap<String, Series> = HashMap::new();
    for batch in wants.chunks(BATCH) {
        let mut pages = cw
            .get_metric_data()
            .set_metric_data_queries(Some(batch.iter().map(Want::query).collect()))
            .start_time(AwsTime::from_secs((now - Duration::days(7)).timestamp()))
            .end_time(AwsTime::from_secs(now.timestamp()))
            .into_paginator()
            .send();
        while let Some(page) = pages.next().await {
            for r in page.map_err(provider_err)?.metric_data_results() {
                let s = got
                    .entry(r.id().unwrap_or_default().to_owned())
                    .or_default();
                s.values.extend_from_slice(r.values());
                s.complete = r.status_code() == Some(&StatusCode::Complete);
            }
        }
    }
    Ok(got)
}

/// Sets `cpu_avg_7d` (mean of the hourly averages) on each running instance. Left `null` when
/// the read failed, CloudWatch did not call it complete, or fewer than `MIN_CPU_POINTS` hours
/// exist. Returns the failure of the read, if any.
pub async fn ec2_cpu(
    cw: &aws_sdk_cloudwatch::Client,
    instances: &mut Option<Result<Vec<Resource>>>,
    now: DateTime<Utc>,
) -> Option<ConnectorError> {
    let Some(Ok(all)) = instances.as_mut() else {
        return None;
    };
    let mut running: Vec<&mut Resource> = all
        .iter_mut()
        .filter(|r| r.attributes["state"] == "running")
        .collect();
    let wants: Vec<Want> = running
        .iter()
        .enumerate()
        .filter_map(|(i, r)| {
            let (_, id) = instance_from_arn(&r.identity).ok()?;
            Some(Want::new(
                i,
                "AWS/EC2",
                "CPUUtilization",
                "Average",
                ("InstanceId", id),
            ))
        })
        .collect();
    let got = match read(cw, &wants, now).await {
        Ok(g) => g,
        Err(e) => return Some(e),
    };
    for (i, r) in running.iter_mut().enumerate() {
        let avg = got.get(&format!("m{i}")).and_then(|s| {
            (s.complete && s.values.len() >= MIN_CPU_POINTS)
                .then(|| s.values.iter().sum::<f64>() / s.values.len() as f64)
        });
        r.attributes["cpu_avg_7d"] = json!(avg);
    }
    None
}

/// The `LoadBalancer` dimension: `app/<name>/<id>` or `net/<name>/<id>` from the ARN.
fn lb_dimension(arn: &str) -> Option<&str> {
    arn.split_once(":loadbalancer/").map(|(_, d)| d)
}

/// Sets `request_count_7d` (application) or `processed_bytes_7d` (network) on each load
/// balancer created 7 or more days ago: the 7-day sum. CloudWatch publishes these only while
/// there is traffic, so a complete read with no points is 0; an incomplete read stays `null`.
/// Younger balancers and gateway balancers stay `null` too. Returns the failure of the read.
pub async fn lb_traffic(
    cw: &aws_sdk_cloudwatch::Client,
    balancers: &mut Option<Result<Vec<Resource>>>,
    now: DateTime<Utc>,
) -> Option<ConnectorError> {
    let Some(Ok(all)) = balancers.as_mut() else {
        return None;
    };
    let week_old = |r: &Resource| {
        r.attributes["created_at"]
            .as_str()
            .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
            .is_some_and(|t| t <= now - Duration::days(7))
    };
    let mut aged: Vec<(&mut Resource, &'static str)> = vec![];
    let mut wants = vec![];
    for r in all.iter_mut().filter(|r| week_old(r)) {
        let (ns, metric, key) = match r.attributes["lb_type"].as_str() {
            Some("application") => ("AWS/ApplicationELB", "RequestCount", "request_count_7d"),
            Some("network") => ("AWS/NetworkELB", "ProcessedBytes", "processed_bytes_7d"),
            _ => continue,
        };
        let Some(dim) = lb_dimension(&r.identity) else {
            continue;
        };
        wants.push(Want::new(
            aged.len(),
            ns,
            metric,
            "Sum",
            ("LoadBalancer", dim),
        ));
        aged.push((r, key));
    }
    let got = match read(cw, &wants, now).await {
        Ok(g) => g,
        Err(e) => return Some(e),
    };
    for (i, (r, key)) in aged.into_iter().enumerate() {
        // A query CloudWatch did not answer at all is unknown, not idle.
        let total = got
            .get(&format!("m{i}"))
            .filter(|s| s.complete)
            .map(|s| s.values.iter().sum::<f64>().round() as u64);
        r.attributes[key] = json!(total);
    }
    None
}
