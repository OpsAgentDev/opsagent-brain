//! Account-level logging and detection: CloudTrail trails, GuardDuty detectors.
use super::Target;
use crate::aws::client::provider_err;
use crate::Result;
use opsagent_core::resource::{resource_identity, Resource, ResourceKind};
use serde_json::json;
use std::collections::BTreeMap;

pub async fn cloudtrails(ct: &aws_sdk_cloudtrail::Client, t: &Target<'_>) -> Result<Vec<Resource>> {
    // Shadow trails included so organization trails (owned by another account) show up;
    // a multi-region trail repeats per region, so dedupe by ARN.
    let trails = ct
        .describe_trails()
        .include_shadow_trails(true)
        .send()
        .await
        .map_err(provider_err)?;
    let mut out = vec![];
    let mut seen = std::collections::HashSet::new();
    for tr in trails.trail_list() {
        let arn = tr.trail_arn().unwrap_or_default();
        if !seen.insert(arn) {
            continue;
        }
        let mut attrs = json!({
            "service": "cloudtrail",
            "is_organization": tr.is_organization_trail().unwrap_or(false),
        });
        // A refused status call (e.g. an organization trail of another account) leaves
        // `logging` and `bucket_writable` absent rather than failing the read.
        match ct.get_trail_status().name(arn).send().await {
            Ok(status) => {
                attrs["logging"] = status.is_logging().unwrap_or(false).into();
                // A delivery error means the trail cannot write to its bucket.
                attrs["bucket_writable"] = status
                    .latest_delivery_error()
                    .is_none_or(str::is_empty)
                    .into();
            }
            Err(e) => {
                let e = provider_err(e);
                let code = match &e {
                    crate::ConnectorError::Api { code, .. } => code.as_deref(),
                    _ => None,
                };
                tracing::debug!(error_code = ?code, "trail status unavailable");
            }
        }
        out.push(t.resource(
            ResourceKind::Log,
            arn.to_owned(),
            tr.name().unwrap_or_default(),
            BTreeMap::new(),
            attrs,
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
