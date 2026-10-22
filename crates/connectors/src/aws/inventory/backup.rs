//! AWS Backup: plans (with the resources their recent jobs covered), vaults, and coverage.
//! Coverage comes from jobs rather than selections so tag- and wildcard-based selections and
//! `NotResources` are resolved by AWS itself.
use super::{rfc3339, Target};
use crate::aws::client::provider_err;
use crate::Result;
use aws_sdk_backup::types::BackupJobState;
use chrono::{DateTime, Duration, Utc};
use opsagent_core::resource::{Resource, ResourceKind};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

/// Jobs older than this do not count; covers weekly and monthly schedules.
const JOB_WINDOW_DAYS: i64 = 35;

/// Latest job per `(plan id, resource arn)`: `(created secs, state)`, plus each plan's roles.
#[derive(Default)]
struct Jobs {
    latest: BTreeMap<(String, String), (i64, BackupJobState)>,
    roles: BTreeMap<String, BTreeSet<String>>,
}

async fn recent_jobs(b: &aws_sdk_backup::Client, now: DateTime<Utc>) -> Result<Jobs> {
    let since = aws_sdk_backup::primitives::DateTime::from_secs(
        (now - Duration::days(JOB_WINDOW_DAYS)).timestamp(),
    );
    let mut jobs = Jobs::default();
    let mut pages = b
        .list_backup_jobs()
        .by_created_after(since)
        .into_paginator()
        .send();
    while let Some(page) = pages.next().await {
        for j in page.map_err(provider_err)?.backup_jobs() {
            let plan = j.created_by().and_then(|c| c.backup_plan_id());
            let (Some(plan), Some(res), Some(state)) = (plan, j.resource_arn(), j.state()) else {
                continue;
            };
            let at = j.creation_date().map_or(0, |d| d.secs());
            let e = jobs.latest.entry((plan.to_owned(), res.to_owned()));
            let e = e.or_insert((at, state.clone()));
            if at >= e.0 {
                *e = (at, state.clone());
            }
            if let Some(role) = j.iam_role_arn() {
                jobs.roles
                    .entry(plan.to_owned())
                    .or_default()
                    .insert(role.to_owned());
            }
        }
    }
    Ok(jobs)
}

/// `last_job_status`: the first covered resource whose latest job ended badly, else the
/// state of the plan's newest job. `null` without jobs in the window.
fn plan_attributes(jobs: &Jobs, plan_id: &str) -> serde_json::Value {
    let mine: Vec<(&String, &(i64, BackupJobState))> = jobs
        .latest
        .iter()
        .filter(|((p, _), _)| p == plan_id)
        .map(|((_, r), v)| (r, v))
        .collect();
    let bad = |s: &BackupJobState| {
        !matches!(
            s,
            BackupJobState::Completed
                | BackupJobState::Created
                | BackupJobState::Pending
                | BackupJobState::Running
        )
    };
    let newest = mine.iter().max_by_key(|(_, (at, _))| *at);
    let status = mine
        .iter()
        .find(|(_, (_, s))| bad(s))
        .or(newest)
        .map(|(_, (_, s))| s.as_str());
    let at = newest.and_then(|(_, (at, _))| DateTime::from_timestamp(*at, 0));
    json!({
        "service": "backup",
        "plan": true,
        "selections": mine.iter().map(|(r, _)| r).collect::<Vec<_>>(),
        "last_job_status": status,
        "last_job_at": at.map(rfc3339),
        "iam_role_arns": jobs.roles.get(plan_id).cloned().unwrap_or_default(),
    })
}

fn vault(t: &Target<'_>, arn: &str, name: &str, cross_account: bool) -> Resource {
    t.resource(
        ResourceKind::Storage,
        arn.to_owned(),
        name,
        BTreeMap::new(),
        json!({"service": "backup", "vault": true, "cross_account": cross_account}),
    )
}

/// Copy-action destinations in another account, from the plan's rules.
async fn cross_account_targets(
    b: &aws_sdk_backup::Client,
    t: &Target<'_>,
    plan_id: &str,
) -> Result<Vec<String>> {
    let p = b
        .get_backup_plan()
        .backup_plan_id(plan_id)
        .send()
        .await
        .map_err(provider_err)?;
    Ok(p.backup_plan()
        .map(|p| p.rules())
        .unwrap_or_default()
        .iter()
        .flat_map(|r| r.copy_actions())
        .map(|c| c.destination_backup_vault_arn().to_owned())
        .filter(|arn| arn.split(':').nth(4).is_some_and(|a| a != t.account))
        .collect())
}

/// Plans, owned vaults, and cross-account copy destinations as `cross_account` vaults.
pub async fn backups(
    b: &aws_sdk_backup::Client,
    t: &Target<'_>,
    now: DateTime<Utc>,
) -> Result<Vec<Resource>> {
    let jobs = recent_jobs(b, now).await?;
    let (mut out, mut remote) = (vec![], BTreeSet::new());
    let mut plans = b.list_backup_plans().into_paginator().send();
    while let Some(page) = plans.next().await {
        for p in page.map_err(provider_err)?.backup_plans_list() {
            let id = p.backup_plan_id().unwrap_or_default();
            remote.extend(cross_account_targets(b, t, id).await?);
            out.push(t.resource(
                ResourceKind::Storage,
                p.backup_plan_arn().unwrap_or(id).to_owned(),
                p.backup_plan_name().unwrap_or(id),
                BTreeMap::new(),
                plan_attributes(&jobs, id),
            ));
        }
    }
    let mut vaults = b.list_backup_vaults().into_paginator().send();
    while let Some(page) = vaults.next().await {
        for v in page.map_err(provider_err)?.backup_vault_list() {
            let name = v.backup_vault_name().unwrap_or_default();
            out.push(vault(t, v.backup_vault_arn().unwrap_or(name), name, false));
        }
    }
    for arn in &remote {
        out.push(vault(t, arn, arn.rsplit(':').next().unwrap_or(arn), true));
    }
    Ok(out)
}

/// Sets `in_backup_plan` on RDS instances: true when a plan's recent jobs covered it.
pub fn mark_backup_coverage(rds: &mut [Resource], backup: &[Resource]) {
    let covered: BTreeSet<&str> = backup
        .iter()
        .filter(|r| r.attributes["plan"] == true)
        .flat_map(|r| r.attributes["selections"].as_array().into_iter().flatten())
        .filter_map(|s| s.as_str())
        .collect();
    for r in rds
        .iter_mut()
        .filter(|r| r.service() == "rds" && r.attributes["snapshot"] != true)
    {
        let hit = covered.contains(r.identity.as_str());
        r.attributes["in_backup_plan"] = json!(hit);
    }
}
