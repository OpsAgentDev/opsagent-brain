//! GPU and training: 24 h GPU utilisation on accelerated instances, SageMaker training jobs.
//! Training jobs come from `ListTrainingJobs` only: the role template denies
//! `sagemaker:DescribeTrainingJob` (it returns hyperparameters and environment).
use super::{rfc3339_aws, Target};
use crate::aws::client::provider_err;
use crate::aws::metrics::{instance_from_arn, metric_points};
use crate::{ConnectorError, Result};
use aws_sdk_sagemaker::types::{SortBy, SortOrder, TrainingJobStatus};
use chrono::{DateTime, Utc};
use opsagent_core::resource::{Resource, ResourceKind};
use serde_json::json;
use std::collections::BTreeMap;

/// Sets `gpu_util_24h` (mean of hourly agent points, `null` without data, when not running,
/// or when the read failed) on every `accelerated` instance. Returns the first failure.
pub async fn gpu_utilisation(
    cw: &aws_sdk_cloudwatch::Client,
    instances: &mut [Resource],
    now: DateTime<Utc>,
) -> Option<ConnectorError> {
    let mut first = None;
    for r in instances
        .iter_mut()
        .filter(|r| r.attributes["accelerated"] == true)
    {
        let mut avg = None;
        if r.attributes["state"] == "running" {
            let points = match instance_from_arn(&r.identity) {
                Ok((_, id)) => metric_points(cw, id, "gpu_util_avg", 24, now).await,
                Err(e) => Err(e),
            };
            match points {
                Ok(p) if !p.is_empty() => {
                    avg = Some(p.iter().map(|x| x.value).sum::<f64>() / p.len() as f64);
                }
                Ok(_) => {}
                Err(e) => {
                    first.get_or_insert(e);
                }
            }
        }
        r.attributes["gpu_util_24h"] = json!(avg);
    }
    first
}

/// Job name without its trailing run id (`resnet-20260929` -> `resnet`).
fn name_prefix(name: &str) -> &str {
    name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '-')
}

/// Median runtime of the last 20 completed jobs sharing `prefix`, in seconds.
async fn median_runtime(sm: &aws_sdk_sagemaker::Client, prefix: &str) -> Result<Option<u64>> {
    if prefix.is_empty() {
        return Ok(None);
    }
    let out = sm
        .list_training_jobs()
        .status_equals(TrainingJobStatus::Completed)
        .name_contains(prefix)
        .sort_by(SortBy::CreationTime)
        .sort_order(SortOrder::Descending)
        .max_results(100)
        .send()
        .await
        .map_err(provider_err)?;
    let mut runs: Vec<u64> = out
        .training_job_summaries()
        .iter()
        .filter(|j| {
            j.training_job_name()
                .is_some_and(|n| name_prefix(n) == prefix)
        })
        .filter_map(|j| {
            let s = j.creation_time()?.secs();
            u64::try_from(j.training_end_time()?.secs() - s).ok()
        })
        .take(20)
        .collect();
    runs.sort_unstable();
    Ok((!runs.is_empty()).then(|| runs[(runs.len() - 1) / 2]))
}

/// In-progress training jobs with the median runtime of their history.
pub async fn training_jobs(
    sm: &aws_sdk_sagemaker::Client,
    t: &Target<'_>,
) -> Result<Vec<Resource>> {
    let mut medians: BTreeMap<String, Option<u64>> = BTreeMap::new();
    let mut out = vec![];
    let mut pages = sm
        .list_training_jobs()
        .status_equals(TrainingJobStatus::InProgress)
        .into_paginator()
        .send();
    while let Some(page) = pages.next().await {
        for j in page.map_err(provider_err)?.training_job_summaries() {
            let name = j.training_job_name().unwrap_or_default();
            let prefix = name_prefix(name);
            let median = match medians.get(prefix) {
                Some(m) => *m,
                None => {
                    let m = median_runtime(sm, prefix).await?;
                    medians.insert(prefix.to_owned(), m);
                    m
                }
            };
            let attrs = json!({
                "service": "sagemaker",
                "job": true,
                "status": j.training_job_status().map(|s| s.as_str()),
                "started_at": j.creation_time().and_then(rfc3339_aws),
                "median_runtime_s": median,
            });
            let arn = j.training_job_arn().unwrap_or(name).to_owned();
            out.push(t.resource(ResourceKind::Job, arn, name, BTreeMap::new(), attrs));
        }
    }
    Ok(out)
}
