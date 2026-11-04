//! RDS: instances and snapshots.
use super::Target;
use crate::aws::client::provider_err;
use crate::Result;
use opsagent_core::resource::{Resource, ResourceKind};
use serde_json::json;
use std::collections::BTreeMap;

pub async fn rds_instances(rds: &aws_sdk_rds::Client, t: &Target<'_>) -> Result<Vec<Resource>> {
    let mut out = vec![];
    let mut pages = rds.describe_db_instances().into_paginator().send();
    while let Some(page) = pages.next().await {
        for db in page.map_err(provider_err)?.db_instances() {
            let attrs = json!({
                "service": "rds",
                "publicly_accessible": db.publicly_accessible(),
                // A cluster member's storage is the cluster's: `rds_clusters` reports it once.
                "encrypted": if db.db_cluster_identifier().is_some() { None } else { db.storage_encrypted() },
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

/// Aurora and Multi-AZ DB clusters; own service so checks 03 and 04 (instances) never see them.
pub async fn rds_clusters(rds: &aws_sdk_rds::Client, t: &Target<'_>) -> Result<Vec<Resource>> {
    let mut out = vec![];
    let mut pages = rds.describe_db_clusters().into_paginator().send();
    while let Some(page) = pages.next().await {
        for c in page.map_err(provider_err)?.db_clusters() {
            out.push(t.resource(
                ResourceKind::Database,
                c.db_cluster_arn().unwrap_or_default().to_owned(),
                c.db_cluster_identifier().unwrap_or_default(),
                BTreeMap::new(),
                json!({"service": "rds_cluster", "encrypted": c.storage_encrypted()}),
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
                json!({"service": "rds", "snapshot": true, "public": public, "encrypted": s.encrypted()}),
            ));
        }
    }
    Ok(out)
}

/// Manual Aurora and Multi-AZ cluster snapshots; own service, only their encryption flag is read.
pub async fn rds_cluster_snapshots(
    rds: &aws_sdk_rds::Client,
    t: &Target<'_>,
) -> Result<Vec<Resource>> {
    let mut out = vec![];
    let mut pages = rds
        .describe_db_cluster_snapshots()
        .snapshot_type("manual")
        .into_paginator()
        .send();
    while let Some(page) = pages.next().await {
        for s in page.map_err(provider_err)?.db_cluster_snapshots() {
            out.push(t.resource(
                ResourceKind::Database,
                s.db_cluster_snapshot_arn().unwrap_or_default().to_owned(),
                s.db_cluster_snapshot_identifier().unwrap_or_default(),
                BTreeMap::new(),
                json!({"service": "rds_cluster_snapshot", "encrypted": s.storage_encrypted()}),
            ));
        }
    }
    Ok(out)
}
