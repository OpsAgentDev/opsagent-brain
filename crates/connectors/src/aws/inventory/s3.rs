//! S3 buckets (global listing, per-bucket region).
use super::service_error;
use super::Target;
use crate::aws::client::provider_err;
use crate::Result;
use crate::ServiceError;
use aws_config::{Region, SdkConfig};
use aws_sdk_s3::error::ProvideErrorMetadata;
use opsagent_core::resource::{Resource, ResourceKind};
use serde_json::json;
use std::collections::BTreeMap;
use std::collections::HashMap;

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
