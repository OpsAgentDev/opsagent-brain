//! AWS Backup: plans with the resources they select, vaults, and RDS coverage.
//! Coverage is the selections' explicit resource ARNs; a selection by tag or wildcard also
//! covers every resource a job of that plan backed up. Jobs set only `last_job_status` and
//! `last_job_at`.
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

/// Latest finished job per `(plan id, resource arn)`: `(created secs, "COMPLETED" | "FAILED")`.
type Jobs = BTreeMap<(String, String), (i64, &'static str)>;

/// Running and queued jobs have no outcome yet and are skipped.
fn outcome(s: &BackupJobState) -> Option<&'static str> {
    match s {
        BackupJobState::Completed => Some("COMPLETED"),
        BackupJobState::Failed
        | BackupJobState::Aborted
        | BackupJobState::Expired
        | BackupJobState::Partial => Some("FAILED"),
        _ => None,
    }
}

async fn recent_jobs(b: &aws_sdk_backup::Client, now: DateTime<Utc>) -> Result<Jobs> {
    let since = aws_sdk_backup::primitives::DateTime::from_secs(
        (now - Duration::days(JOB_WINDOW_DAYS)).timestamp(),
    );
    let mut jobs = Jobs::new();
    let mut pages = b
        .list_backup_jobs()
        .by_created_after(since)
        .into_paginator()
        .send();
    while let Some(page) = pages.next().await {
        for j in page.map_err(provider_err)?.backup_jobs() {
            let plan = j.created_by().and_then(|c| c.backup_plan_id());
            let state = j.state().and_then(outcome);
            let (Some(plan), Some(res), Some(state)) = (plan, j.resource_arn(), state) else {
                continue;
            };
            let at = j.creation_date().map_or(0, |d| d.secs());
            let e = jobs
                .entry((plan.to_owned(), res.to_owned()))
                .or_insert((at, state));
            if at >= e.0 {
                *e = (at, state);
            }
        }
    }
    Ok(jobs)
}

/// What a plan's selections name: explicit ARNs, whether any selects by tag or wildcard, roles.
#[derive(Default)]
struct Selected {
    explicit: BTreeSet<String>,
    dynamic: bool,
    roles: BTreeSet<String>,
}

async fn selections(b: &aws_sdk_backup::Client, plan_id: &str) -> Result<Selected> {
    let mut out = Selected::default();
    let mut pages = b
        .list_backup_selections()
        .backup_plan_id(plan_id)
        .into_paginator()
        .send();
    while let Some(page) = pages.next().await {
        for m in page.map_err(provider_err)?.backup_selections_list() {
            let got = b
                .get_backup_selection()
                .backup_plan_id(plan_id)
                .selection_id(m.selection_id().unwrap_or_default())
                .send()
                .await
                .map_err(provider_err)?;
            let Some(sel) = got.backup_selection() else {
                continue;
            };
            for r in sel.resources() {
                if r.contains('*') {
                    out.dynamic = true;
                } else {
                    out.explicit.insert(r.clone());
                }
            }
            out.dynamic |= !sel.list_of_tags().is_empty();
            out.roles.insert(sel.iam_role_arn().to_owned());
        }
    }
    Ok(out)
}

/// `last_job_status`: FAILED when any covered resource's latest finished job failed, else
/// COMPLETED when one completed, else `null` (selected but never ran in the window).
fn plan_attributes(jobs: &Jobs, plan_id: &str, sel: Selected) -> serde_json::Value {
    let mut covered = sel.explicit;
    if sel.dynamic {
        covered.extend(
            jobs.keys()
                .filter(|(p, _)| p == plan_id)
                .map(|(_, r)| r.clone()),
        );
    }
    let runs: Vec<(i64, &str)> = covered
        .iter()
        .filter_map(|r| jobs.get(&(plan_id.to_owned(), r.clone())).copied())
        .collect();
    let status = ["FAILED", "COMPLETED"]
        .into_iter()
        .find(|s| runs.iter().any(|(_, x)| x == s));
    let at = runs.iter().map(|(at, _)| *at).max();
    json!({
        "service": "backup",
        "plan": true,
        "selections": covered,
        "last_job_status": status,
        "last_job_at": at.and_then(|a| DateTime::from_timestamp(a, 0)).map(rfc3339),
        "iam_role_arns": sel.roles,
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
            let sel = selections(b, id).await?;
            out.push(t.resource(
                ResourceKind::Storage,
                p.backup_plan_arn().unwrap_or(id).to_owned(),
                p.backup_plan_name().unwrap_or(id),
                BTreeMap::new(),
                plan_attributes(&jobs, id, sel),
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

/// Sets `in_backup_plan` on RDS instances: true when some plan's `selections` names it.
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
