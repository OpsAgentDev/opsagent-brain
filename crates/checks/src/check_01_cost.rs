use crate::ctx::{draft, svc, Check, CheckCtx};
use opsagent_connectors::Capability;
use opsagent_core::finding::{Evidence, FindingDraft, FindingKey, Severity};
use opsagent_core::resource::Provider;
use std::collections::BTreeMap;

pub struct CostAndIdle;

fn by_dollars(usd: f64) -> Severity {
    if usd >= 100.0 {
        Severity::High
    } else if usd >= 20.0 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

fn mean_sd(v: &[f64]) -> (f64, f64) {
    let m = v.iter().sum::<f64>() / v.len() as f64;
    (
        m,
        (v.iter().map(|x| (x - m).powi(2)).sum::<f64>() / v.len() as f64).sqrt(),
    )
}

impl Check for CostAndIdle {
    fn id(&self) -> &'static str {
        "01"
    }
    fn supported(&self) -> &[Provider] {
        &[Provider::Aws, Provider::Fake]
    }
    fn required(&self) -> &[Capability] {
        &[Capability::Inventory]
    }

    fn run(&self, ctx: &CheckCtx) -> Vec<FindingDraft> {
        let mut out = vec![];
        for r in ctx.resources {
            let a = &r.attributes;
            let usd = a["monthly_cost_usd"].as_f64().unwrap_or(0.0);
            let (variant, title, step, excerpt) = match svc(r) {
                "ebs" if a["attached"] == false => (
                    "unattached_volume",
                    format!("Unattached volume {}", r.identity),
                    "Snapshot it if needed, then delete the volume.",
                    format!("attached=false size_gb={}", a["size_gb"]),
                ),
                "eip" if a["associated"] == false => (
                    "unassociated_address",
                    format!("Unassociated address {}", r.identity),
                    "Release the address if it is not reserved on purpose.",
                    "associated=false".to_owned(),
                ),
                "elb" if a["request_count_7d"].as_u64() == Some(0) => (
                    "idle_load_balancer",
                    format!("Idle load balancer {}", r.identity),
                    "Confirm nothing routes here and delete the load balancer.",
                    "request_count_7d=0".to_owned(),
                ),
                "ec2"
                    if a["state"] == "running"
                        && a["cpu_avg_7d"].as_f64().is_some_and(|c| c < 5.0) =>
                {
                    (
                        "idle_instance",
                        format!("Idle instance {}", r.identity),
                        "Stop or downsize the instance if the low load is expected to last.",
                        format!("state=running cpu_avg_7d={}", a["cpu_avg_7d"]),
                    )
                }
                _ => continue,
            };
            let summary = format!("{title}, costing about ${usd:.2}/month.");
            out.push(draft(
                ctx,
                "01",
                r,
                variant,
                by_dollars(usd),
                (title, summary, step),
                excerpt,
            ));
        }
        out.extend(anomaly(ctx));
        out
    }
}

/// Daily totals, last 2 days dropped; each of the final 7 remaining days is tested
/// against mean+3 sigma of the 7 and 30 days before it (both must be exceeded).
// shortcut: windows with <3 prior days are skipped, revisit if short histories matter.
fn anomaly(ctx: &CheckCtx) -> Vec<FindingDraft> {
    let mut days: BTreeMap<_, f64> = BTreeMap::new();
    for c in ctx.cost {
        *days.entry(c.date).or_default() += c.amount_usd;
    }
    let s: Vec<_> = days.into_iter().collect();
    let n = s.len().saturating_sub(2);
    let mut out = vec![];
    for i in n.saturating_sub(7)..n {
        let (date, amt) = s[i];
        let base = |w: usize| {
            let p: Vec<f64> = s[i.saturating_sub(w)..i].iter().map(|x| x.1).collect();
            (p.len() >= 3).then(|| mean_sd(&p))
        };
        let (Some((m7, sd7)), Some((m30, sd30))) = (base(7), base(30)) else {
            continue;
        };
        // Floor (5% of mean or one cent) keeps float noise on flat series from flagging.
        let floor = |m: f64| (0.05 * m).max(0.01);
        if !(amt > m7 + 3.0 * sd7 + floor(m7) && amt > m30 + 3.0 * sd30 + floor(m30)) {
            continue;
        }
        let pct = (amt - m30) / m30.max(f64::EPSILON) * 100.0;
        let sev = if pct >= 20.0 && amt - m30 >= 50.0 {
            Severity::High
        } else {
            Severity::Medium
        };
        let excerpt =
            format!("{date}: ${amt:.2} vs baseline ${m30:.2} (30d mean), ${m7:.2} (7d mean)");
        out.push(FindingDraft {
            key: FindingKey {
                connection_id: ctx.connection_id,
                check_id: "01".into(),
                resource_identity: format!("cost:{date}"),
                variant: "cost_anomaly".into(),
            },
            severity: sev,
            title: format!("Cost spike on {date}"),
            summary: format!(
                "Spend was ${amt:.2} on {date}, {pct:.0}% above the ${m30:.2} baseline."
            ),
            next_step: "Open Cost Explorer for that day and find the service that moved.".into(),
            cost_monthly_usd: None,
            evidence: vec![Evidence {
                source: format!("cost:{date}"),
                excerpt,
            }],
        });
    }
    out
}
