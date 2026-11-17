use crate::ctx::{draft, short, Check, CheckCtx};
use opsagent_connectors::Capability;
use opsagent_core::finding::{FindingDraft, Severity};
use opsagent_core::resource::Provider;

pub struct Backups;

impl Check for Backups {
    fn id(&self) -> &'static str {
        "04"
    }
    fn supported(&self) -> &[Provider] {
        &[Provider::Aws, Provider::Fake]
    }
    fn required(&self) -> &[Capability] {
        &[Capability::Backups]
    }

    fn run(&self, ctx: &CheckCtx) -> Vec<FindingDraft> {
        let mut out = vec![];
        for r in ctx.resources {
            let a = &r.attributes;
            let (n, id) = (short(r), &r.identity);
            let mut push = |variant, sev, title: String, summary: String, step, ex: String| {
                out.push(draft(
                    ctx,
                    "04",
                    r,
                    variant,
                    sev,
                    (title, summary, step),
                    ex,
                ));
            };
            match r.service() {
                // A missing `in_backup_plan` key means coverage could not be read: skip, never "uncovered".
                "ec2" | "ebs" | "rds" => {
                    let Some(covered) = a["in_backup_plan"].as_bool() else {
                        continue;
                    };
                    // RDS automated backups (retention of a day or more) restore the database without a plan.
                    let automated = r.service() == "rds"
                        && a["backup_retention_days"].as_i64().unwrap_or(0) > 0;
                    if !covered && !automated {
                        push(
                            "not_in_plan",
                            Severity::Medium,
                            format!("{n} is not in any backup plan"),
                            format!("{id} has no backup plan selecting it."),
                            "Without a backup, a deleted or corrupted resource cannot be restored. AWS Backup console > Backup plans > the plan > Assign resources, and add this resource.",
                            "in_backup_plan=false".into(),
                        );
                    } else if covered && a["backup_last_job_status"].is_null() && !automated {
                        // A plan selects it, but no job finished in the window: a plan with no
                        // rules, a paused schedule, or a backup that never started.
                        push(
                            "no_recent_backup",
                            Severity::Medium,
                            format!("{n} has no finished backup in the last 35 days"),
                            format!("A backup plan selects {id}, but no backup job for it finished in the last 35 days."),
                            "A plan that never finishes a job leaves no restore point. AWS Backup console > Backup plans: check the rule's schedule, then Protected resources > Create on-demand backup.",
                            "in_backup_plan=true backup_last_job_status=null".into(),
                        );
                    } else if a["backup_last_job_status"] == "FAILED" {
                        let at = a["backup_last_job_at"].as_str().unwrap_or("unknown");
                        push(
                            "last_job_failed",
                            Severity::High,
                            format!("Last backup job for {n} failed"),
                            format!("The most recent backup job for {id} ended FAILED."),
                            "Until a job succeeds, the newest restore point is older than you think. AWS Backup console > Jobs > the failed job shows the reason; fix it, then Create on-demand backup.",
                            format!("backup_last_job_status=FAILED backup_last_job_at={at}"),
                        );
                    }
                    if r.service() == "rds" && a["backup_retention_days"] == 1 {
                        push(
                            "retention_1d",
                            Severity::Medium,
                            format!("Database {n} keeps backups for 1 day"),
                            format!("{id} has automated backup retention of 1 day."),
                            "One day of backups cannot recover from a problem noticed after a weekend. RDS console > Databases > Modify > Backup retention period: 7 days or more, or `aws rds modify-db-instance --db-instance-identifier <id> --backup-retention-period 7`.",
                            "backup_retention_days=1".into(),
                        );
                    }
                }
                "backup" if a["plan"] == true => {
                    let roles: Vec<&str> = a["iam_role_arns"]
                        .as_array()
                        .map(|v| v.iter().filter_map(|x| x.as_str()).collect())
                        .unwrap_or_default();
                    let sims: Vec<_> = roles
                        .iter()
                        .filter_map(|r| ctx.simulations.get(*r))
                        .collect();
                    let denied: Vec<&str> = sims
                        .iter()
                        .flat_map(|s| s.denied.iter().map(String::as_str))
                        .collect();
                    if !denied.is_empty() {
                        push(
                            "restore_perms_missing",
                            Severity::High,
                            format!("Backup role for {n} cannot restore"),
                            format!("Restore actions are denied for the backup role of {id}."),
                            "Backups this role cannot restore fail when they are needed most. IAM console > Roles > the backup role > Add permissions, and grant the denied actions in the evidence (the AWSBackupServiceRolePolicyForRestores managed policy covers them).",
                            format!("denied={denied:?}"),
                        );
                    } else if sims.len() < roles.len() || sims.iter().all(|s| s.allowed.is_empty())
                    {
                        push(
                            "coverage_unknown",
                            Severity::Info,
                            format!("Restore permissions for {n} could not be verified"),
                            format!("The restore simulation for {id} was missing or undecided."),
                            "OpsAgent could not confirm the role can restore, so a restore may fail. Test the restore actions in the IAM policy simulator for the backup role, or run a test restore in AWS Backup console > Protected resources.",
                            format!("iam_role_arns={roles:?}"),
                        );
                    }
                }
                "backup" if a["vault"] == true && a["cross_account"] == true => push(
                    "coverage_unknown",
                    Severity::Info,
                    format!("Vault {n} is in another account"),
                    format!("Backups in {id} cannot be inspected from this account."),
                    "Backups in another account are outside this connection's view. Connect the owning account to OpsAgent, or review it in that account's AWS Backup console > Backup vaults.",
                    "cross_account=true".into(),
                ),
                _ => {}
            }
        }
        out
    }
}
