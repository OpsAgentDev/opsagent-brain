//! CloudWatch `GetMetricData` for EC2 instances: `cpu_avg` (AWS/EC2) and `gpu_util_avg`
//! (CloudWatch agent `nvidia_smi_utilization_gpu`, empty when the agent does not publish it).
use super::client::provider_err;
use crate::{ConnectorError, MetricPoint, Result};
use aws_sdk_cloudwatch::primitives::DateTime as AwsTime;
use aws_sdk_cloudwatch::types::{Dimension, Metric, MetricDataQuery, MetricStat};
use chrono::{DateTime, Duration, Utc};

pub const METRIC_ACTIONS: &[&str] = &["cloudwatch:GetMetricData", "cloudwatch:ListMetrics"];

const PERIOD_S: i32 = 3600;

fn aws_time(t: DateTime<Utc>) -> AwsTime {
    AwsTime::from_secs(t.timestamp())
}

fn query(instance_id: &str, metric: &str) -> Result<MetricDataQuery> {
    let q = MetricDataQuery::builder().id("m");
    let q = match metric {
        "cpu_avg" => q.metric_stat(
            MetricStat::builder()
                .metric(
                    Metric::builder()
                        .namespace("AWS/EC2")
                        .metric_name("CPUUtilization")
                        .dimensions(Dimension::builder().name("InstanceId").value(instance_id).build())
                        .build(),
                )
                .period(PERIOD_S)
                .stat("Average")
                .build(),
        ),
        // Agent dimensions vary (index, name, arch), so SEARCH by instance and average the GPUs.
        "gpu_util_avg" => q.expression(format!(
            "AVG(SEARCH('Namespace=\"CWAgent\" MetricName=\"nvidia_smi_utilization_gpu\" InstanceId=\"{instance_id}\"', 'Average', {PERIOD_S}))"
        )),
        _ => return Err(ConnectorError::Provider(format!("unknown metric {metric}"))),
    };
    Ok(q.build())
}

/// Hourly points for the last `hours`, oldest first. `instance_id` is validated because it is
/// interpolated into a SEARCH expression.
pub async fn metric_points(
    cw: &aws_sdk_cloudwatch::Client,
    instance_id: &str,
    metric: &str,
    hours: u32,
    now: DateTime<Utc>,
) -> Result<Vec<MetricPoint>> {
    let valid = instance_id
        .strip_prefix("i-")
        .is_some_and(|h| !h.is_empty() && h.bytes().all(|b| b.is_ascii_alphanumeric()));
    if !valid {
        return Err(ConnectorError::Provider("not an EC2 instance id".into()));
    }
    let mut pages = cw
        .get_metric_data()
        .metric_data_queries(query(instance_id, metric)?)
        .start_time(aws_time(now - Duration::hours(i64::from(hours))))
        .end_time(aws_time(now))
        .into_paginator()
        .send();
    let mut out = vec![];
    while let Some(page) = pages.next().await {
        for r in page.map_err(provider_err)?.metric_data_results() {
            out.extend(r.timestamps().iter().zip(r.values()).filter_map(|(t, v)| {
                Some(MetricPoint {
                    at: DateTime::from_timestamp(t.secs(), t.subsec_nanos())?,
                    value: *v,
                })
            }));
        }
    }
    out.sort_by_key(|p| p.at);
    Ok(out)
}

/// `(region, instance id)` from `arn:<p>:ec2:<region>:<account>:instance/<id>`.
pub fn instance_from_arn(arn: &str) -> Result<(&str, &str)> {
    let parts: Vec<&str> = arn.splitn(6, ':').collect();
    match parts[..] {
        [_, _, "ec2", region, _, res] => res
            .strip_prefix("instance/")
            .map(|id| (region, id))
            .ok_or_else(|| ConnectorError::Provider("not an EC2 instance ARN".into())),
        _ => Err(ConnectorError::Provider("not an EC2 instance ARN".into())),
    }
}
