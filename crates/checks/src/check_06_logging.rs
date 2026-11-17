use crate::ctx::{draft, short, Check, CheckCtx};
use opsagent_connectors::Capability;
use opsagent_core::finding::{Evidence, FindingDraft, FindingKey, Severity};
use opsagent_core::resource::Provider;
use std::collections::BTreeMap;

pub struct LoggingGaps;

const USD_PER_GB_MONTH: f64 = 0.03;

impl Check for LoggingGaps {
    fn id(&self) -> &'static str {
        "06"
    }
    fn supported(&self) -> &[Provider] {
        &[Provider::Aws, Provider::Fake]
    }
    fn required(&self) -> &[Capability] {
        &[Capability::Logging]
    }

    fn run(&self, ctx: &CheckCtx) -> Vec<FindingDraft> {
        let mut out = vec![];
        // account -> trails as (identity, Some(broken)); None = own-account status unknown.
        let mut trails: BTreeMap<&str, Vec<(&str, Option<bool>)>> = BTreeMap::new();
        // account -> regions with GuardDuty off: one finding per account, not per region.
        let mut off: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for r in ctx.resources {
            let a = &r.attributes;
            let acct = trails.entry(r.account.as_str()).or_default();
            match r.service() {
                "cloudtrail" => {
                    let org = a["is_organization"] == true;
                    // ARN account; an organization trail of another account has a bucket
                    // that is not ours to judge.
                    let foreign =
                        org && r.identity.split(':').nth(4).is_some_and(|o| o != r.account);
                    let unwritable = !foreign && a["bucket_writable"] == false;
                    let broken = match a["logging"].as_bool() {
                        Some(false) => Some(true),
                        Some(true) => Some(unwritable),
                        // Unknown status: only a foreign organization trail counts as present.
                        None if foreign => Some(false),
                        None => None,
                    };
                    acct.push((r.identity.as_str(), broken));
                }
                // A missing key means the read failed: skip, never treat as off.
                "guardduty" if a["enabled"] == false && !ctx.unavailable.contains("guardduty") => {
                    off.entry(r.account.as_str()).or_default().push(&r.region);
                }
                "logs"
                    if a["retention_days"].is_null()
                        && a.get("retention_days").is_some()
                        && !ctx.unavailable.contains("logs") =>
                {
                    let gb = a["stored_bytes"].as_f64().map(|b| b / 1e9);
                    let cost = gb.map(|g| g * USD_PER_GB_MONTH);
                    let title = format!("Log group {} never expires", short(r));
                    let s = format!("{} keeps every event forever.", r.identity);
                    let ex = match (gb, cost) {
                        (Some(g), Some(c)) => {
                            format!("retention_days=null stored_gb={g:.1} est_monthly_usd={c:.2}")
                        }
                        _ => "retention_days=null".into(),
                    };
                    let step = "Logs kept forever cost more every month. CloudWatch console > Log groups > the group > Actions > Edit retention setting, or `aws logs put-retention-policy --log-group-name <name> --retention-in-days 90`.";
                    let mut d = draft(
                        ctx,
                        "06",
                        r,
                        "no_retention",
                        Severity::Low,
                        (title, s, step),
                        ex,
                    );
                    d.cost_monthly_usd = cost;
                    out.push(d);
                }
                _ => {}
            }
        }
        for (acct, mut regions) in off {
            regions.sort_unstable();
            let n = regions.len();
            let list = regions.join(", ");
            out.push(account_finding(
                ctx,
                ("guardduty", acct),
                ("detection_off", Severity::High),
                (
                    &format!("Threat detection is off in {n} region{}", if n == 1 { "" } else { "s" }),
                    &format!("GuardDuty is off in {list}."),
                    "Without GuardDuty, stolen credentials, crypto-mining and calls from known bad addresses go unseen in those regions. Enable it in each listed region: GuardDuty console > Get started > Enable GuardDuty, or `aws guardduty create-detector --enable --region <region>`; an organisation can enable it for every account and region from its delegated administrator.",
                ),
                format!("regions with GuardDuty off: {list}"),
            ));
        }
        for (acct, ts) in trails {
            if ctx.unavailable.contains("cloudtrail") || ts.iter().any(|(_, b)| *b == Some(false)) {
                continue;
            }
            // Own-account trails of unknown status are not judged: say so, not "off".
            let unknown: Vec<&str> = ts
                .iter()
                .filter(|(_, b)| b.is_none())
                .map(|(i, _)| *i)
                .collect();
            if !unknown.is_empty() {
                out.push(account_finding(
                    ctx,
                    ("cloudtrail", acct),
                    ("trail_status_unknown", Severity::Medium),
                    (
                        "Audit trail status could not be read",
                        "Could not confirm any trail is logging and able to write to its bucket.",
                        "Without the status, OpsAgent cannot tell whether account activity is being recorded. Grant cloudtrail:GetTrailStatus to the OpsAgent read role (IAM console > Roles > OpsAgentReadRole > Add permissions), then run a scan.",
                    ),
                    format!("trails with unreadable status: {}", unknown.join(", ")),
                ));
                continue;
            }
            let list: Vec<&str> = ts.iter().map(|(i, _)| *i).collect();
            let ex = if list.is_empty() {
                "no trail found".to_owned()
            } else {
                format!(
                    "trails not logging or bucket unwritable: {}",
                    list.join(", ")
                )
            };
            out.push(account_finding(
                ctx,
                ("cloudtrail", acct),
                ("trail_effectively_off", Severity::Critical),
                (
                    "Audit trail is effectively off",
                    "No trail is both logging and able to write to its bucket.",
                    "Without a working trail there is no record of who changed what, which incident response and audits depend on. CloudTrail console > Trails > the trail > Start logging (`aws cloudtrail start-logging --name <trail>`), and make sure its bucket policy lets cloudtrail.amazonaws.com write.",
                ),
                ex,
            ));
        }
        out
    }
}

/// An account-wide finding, keyed `<service>:<account>`.
fn account_finding(
    ctx: &CheckCtx,
    (service, acct): (&str, &str),
    (variant, severity): (&str, Severity),
    (title, summary, step): (&str, &str, &str),
    excerpt: String,
) -> FindingDraft {
    FindingDraft {
        key: FindingKey {
            connection_id: ctx.connection_id,
            check_id: "06".into(),
            resource_identity: format!("{service}:{acct}"),
            variant: variant.into(),
        },
        severity,
        title: title.into(),
        summary: summary.into(),
        next_step: step.into(),
        cost_monthly_usd: None,
        evidence: vec![Evidence {
            source: format!("{service}:{acct}"),
            excerpt,
        }],
    }
}
