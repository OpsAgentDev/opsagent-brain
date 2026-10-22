use crate::ctx::{draft, Check, CheckCtx};
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
        // account -> trails as (identity, Some(broken)); None = status unknown, skipped.
        let mut trails: BTreeMap<&str, Vec<(&str, Option<bool>)>> = BTreeMap::new();
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
                        // Unknown status: an organization trail counts as present.
                        None if org => Some(false),
                        None => None,
                    };
                    acct.push((r.identity.as_str(), broken));
                }
                // A missing key means the read failed: skip, never treat as off.
                "guardduty" if a["enabled"] == false && !ctx.unavailable.contains("guardduty") => {
                    let title = format!("Threat detection is off in {}", r.region);
                    let s = format!("{title}.");
                    let step = "Enable GuardDuty in this region.";
                    let ex = format!("region={} enabled=false", r.region);
                    let variant = format!("detection_off:{}", r.region);
                    out.push(draft(
                        ctx,
                        "06",
                        r,
                        &variant,
                        Severity::High,
                        (title, s, step),
                        ex,
                    ));
                }
                "logs"
                    if a["retention_days"].is_null()
                        && a.get("retention_days").is_some()
                        && !ctx.unavailable.contains("logs") =>
                {
                    let gb = a["stored_bytes"].as_f64().map(|b| b / 1e9);
                    let cost = gb.map(|g| g * USD_PER_GB_MONTH);
                    let title = format!("Log group {} never expires", r.identity);
                    let s = format!("{title}.");
                    let ex = match (gb, cost) {
                        (Some(g), Some(c)) => {
                            format!("retention_days=null stored_gb={g:.1} est_monthly_usd={c:.2}")
                        }
                        _ => "retention_days=null".into(),
                    };
                    let step = "Set a retention period.";
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
        for (acct, ts) in trails {
            if ctx.unavailable.contains("cloudtrail") || ts.iter().any(|(_, b)| *b != Some(true)) {
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
            out.push(FindingDraft {
                key: FindingKey {
                    connection_id: ctx.connection_id,
                    check_id: "06".into(),
                    resource_identity: format!("cloudtrail:{acct}"),
                    variant: "trail_effectively_off".into(),
                },
                severity: Severity::Critical,
                title: "Audit trail is effectively off".into(),
                summary: "No trail is both logging and able to write to its bucket.".into(),
                next_step: "Start logging on a trail and fix its bucket policy.".into(),
                cost_monthly_usd: None,
                evidence: vec![Evidence {
                    source: format!("cloudtrail:{acct}"),
                    excerpt: ex,
                }],
            });
        }
        out
    }
}
