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
            out.roles.insert(sel.iam_role_arn().to_owned());
            // Tags, wildcards and Conditions are resolved by AWS: trust only the jobs.
            let conditioned = sel.conditions().is_some_and(|c| {
                !(c.string_equals().is_empty()
                    && c.string_not_equals().is_empty()
                    && c.string_like().is_empty()
                    && c.string_not_like().is_empty())
            });
            if conditioned
                || !sel.list_of_tags().is_empty()
                || sel.resources().iter().any(|r| r.contains('*'))
            {
                out.dynamic = true;
                continue;
            }
            // shortcut: exact `NotResources` ARNs only; wildcard exclusions need glob matching.
            let excluded: BTreeSet<&String> = sel.not_resources().iter().collect();
            out.explicit.extend(
                sel.resources()
                    .iter()
                    .filter(|r| !excluded.contains(r))
                    .cloned(),
            );
        }
    }
    Ok(out)
}

/// Plan-level display: `last_job_status` is FAILED when any covered resource's latest finished
/// job failed, else COMPLETED when one completed, else `null` (never ran in the window).
/// `resource_jobs` holds each covered resource's latest finished job; `mark_backup_coverage`
/// copies it onto the resource, which is what per-resource findings read.
fn plan_attributes(jobs: &Jobs, plan_id: &str, sel: Selected) -> serde_json::Value {
    let mut covered = sel.explicit;
    if sel.dynamic {
        covered.extend(
            jobs.keys()
                .filter(|(p, _)| p == plan_id)
                .map(|(_, r)| r.clone()),
        );
    }
    let per: BTreeMap<&String, (i64, &str)> = covered
        .iter()
        .filter_map(|r| Some((r, *jobs.get(&(plan_id.to_owned(), r.clone()))?)))
        .collect();
    let runs: Vec<(i64, &str)> = per.values().copied().collect();
    let status = ["FAILED", "COMPLETED"]
        .into_iter()
        .find(|s| runs.iter().any(|(_, x)| x == s));
    let at = runs.iter().map(|(at, _)| *at).max();
    json!({
        "service": "backup",
        "plan": true,
        "selections": covered,
        "last_job_status": status,
        "last_job_at": at.and_then(ts),
        "iam_role_arns": sel.roles,
        "resource_jobs": per
            .iter()
            .map(|(r, (at, st))| (r.to_string(), json!({"status": st, "at": ts(*at)})))
            .collect::<serde_json::Map<_, _>>(),
    })
}

fn ts(secs: i64) -> Option<String> {
    DateTime::from_timestamp(secs, 0).map(rfc3339)
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

/// Sets `in_backup_plan` (some plan's `selections` names it) and `backup_last_job_status` /
/// `backup_last_job_at` (its own most recent finished job across those plans, else `null`)
/// on each resource. Snapshots are skipped.
pub fn mark_backup_coverage(resources: &mut [Resource], backup: &[Resource]) {
    let plans: Vec<&serde_json::Value> = backup
        .iter()
        .filter(|r| r.attributes["plan"] == true)
        .map(|r| &r.attributes)
        .collect();
    for r in resources
        .iter_mut()
        .filter(|r| r.attributes["snapshot"] != true)
    {
        let id = r.identity.as_str();
        let covering = plans.iter().filter(|p| {
            p["selections"]
                .as_array()
                .is_some_and(|s| s.iter().any(|x| x == id))
        });
        let mut hit = false;
        let mut last: Option<&serde_json::Value> = None;
        for p in covering {
            hit = true;
            let job = &p["resource_jobs"][id];
            if job.is_object() && last.is_none_or(|l| job["at"].as_str() > l["at"].as_str()) {
                last = Some(job);
            }
        }
        let a = &mut r.attributes;
        a["in_backup_plan"] = json!(hit);
        a["backup_last_job_status"] = last.map_or(json!(null), |j| j["status"].clone());
        a["backup_last_job_at"] = last.map_or(json!(null), |j| j["at"].clone());
    }
}
