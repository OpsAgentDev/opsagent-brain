//! Certificate Manager certificates. Endpoint presented-certificate mismatch needs a TLS probe
//! and is Plan 3 for AWS; only fixtures emit the `endpoint` shape today.
use super::{rfc3339_aws, service_error, Target};
use crate::aws::client::provider_err;
use crate::{Result, ServiceError};
use aws_sdk_acm::types::{CertificateType, Filters, KeyAlgorithm, RenewalStatus};
use opsagent_core::resource::{Resource, ResourceKind};
use serde_json::json;
use std::collections::BTreeMap;

fn renewal(s: Option<&RenewalStatus>) -> Option<&'static str> {
    match s? {
        RenewalStatus::Success => Some("SUCCESS"),
        RenewalStatus::Failed => Some("FAILED"),
        _ => Some("PENDING"),
    }
}

/// Without `keyTypes` ListCertificates returns RSA_1024/RSA_2048 only, hiding ECDSA certs.
const KEY_TYPES: [KeyAlgorithm; 7] = [
    KeyAlgorithm::Rsa1024,
    KeyAlgorithm::Rsa2048,
    KeyAlgorithm::Rsa3072,
    KeyAlgorithm::Rsa4096,
    KeyAlgorithm::EcPrime256v1,
    KeyAlgorithm::EcSecp384r1,
    KeyAlgorithm::EcSecp521r1,
];

/// Every certificate; one that fails to describe lands in `errs` and the rest still return.
pub async fn certificates(
    acm: &aws_sdk_acm::Client,
    t: &Target<'_>,
    errs: &mut Vec<ServiceError>,
) -> Result<Vec<Resource>> {
    let mut arns = vec![];
    let filters = Filters::builder()
        .set_key_types(Some(KEY_TYPES.to_vec()))
        .build();
    let mut pages = acm
        .list_certificates()
        .includes(filters)
        .into_paginator()
        .send();
    while let Some(page) = pages.next().await {
        let page = page.map_err(provider_err)?;
        arns.extend(
            page.certificate_summary_list()
                .iter()
                .filter_map(|c| c.certificate_arn().map(str::to_owned)),
        );
    }
    let mut out = vec![];
    for arn in arns {
        let d = match acm
            .describe_certificate()
            .certificate_arn(&arn)
            .send()
            .await
        {
            Ok(d) => d,
            Err(e) => {
                errs.push(service_error("acm", t.region, &provider_err(e)));
                continue;
            }
        };
        let Some(c) = d.certificate() else { continue };
        let attrs = json!({
            "service": "acm",
            "not_after": c.not_after().and_then(rfc3339_aws),
            "renewal_status": renewal(c.renewal_summary().map(|r| r.renewal_status())),
            "in_use_by": c.in_use_by(),
            "managed": c.r#type() == Some(&CertificateType::AmazonIssued),
        });
        out.push(t.resource(
            ResourceKind::Certificate,
            arn.clone(),
            c.domain_name().unwrap_or(&arn),
            BTreeMap::new(),
            attrs,
        ));
    }
    Ok(out)
}
