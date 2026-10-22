use crate::ctx::{draft, Check, CheckCtx};
use chrono::{DateTime, Utc};
use opsagent_connectors::Capability;
use opsagent_core::finding::{FindingDraft, Severity};
use opsagent_core::resource::Provider;

pub struct Certificates;

impl Check for Certificates {
    fn id(&self) -> &'static str {
        "05"
    }
    fn supported(&self) -> &[Provider] {
        &[Provider::Aws, Provider::Fake]
    }
    fn required(&self) -> &[Capability] {
        &[Capability::Certificates]
    }

    fn run(&self, ctx: &CheckCtx) -> Vec<FindingDraft> {
        let mut out = vec![];
        for r in ctx.resources.iter().filter(|r| r.service() == "acm") {
            let a = &r.attributes;
            let id = &r.identity;
            // Candidates in worst-first order; the first is the one finding emitted.
            let mut hits: Vec<(Severity, String, &str)> = vec![];
            let mut facts: Vec<String> = vec![];

            if a["presented_serial"].is_string() && a["presented_serial"] != a["expected_serial"] {
                facts.push(format!(
                    "presented_serial={} expected_serial={}",
                    a["presented_serial"].as_str().unwrap_or(""),
                    a["expected_serial"].as_str().unwrap_or("")
                ));
            }
            let mismatch = !facts.is_empty();

            let left = a["not_after"]
                .as_str()
                .and_then(|s| s.parse::<DateTime<Utc>>().ok())
                .map(|t| t - ctx.now);
            let days = left.map(|l| l.num_days());
            if let Some(d) = days {
                facts.push(format!("days_left={d}"));
            }
            // Imported certificates (managed=false) have no renewal status.
            let failed = a["managed"] != false && a["renewal_status"] == "FAILED";
            if failed {
                facts.push("renewal_status=FAILED".into());
            }
            let unattached = a["in_use_by"].as_array().is_some_and(|v| v.is_empty());
            if unattached {
                facts.push("in_use_by=[]".into());
            }

            if let Some(d) = days.filter(|d| *d < 7) {
                hits.push((
                    Severity::Critical,
                    if left.is_some_and(|l| l.num_seconds() < 0) {
                        format!("Certificate {id} expired {} days ago", -d)
                    } else {
                        format!("Certificate {id} expires in {d} days")
                    },
                    "Renew or replace the certificate now.",
                ));
            }
            if failed {
                hits.push((
                    Severity::High,
                    format!("Certificate {id}: managed renewal failed"),
                    "Fix the validation that blocks renewal (DNS record or email approval).",
                ));
            }
            if let Some(d) = days.filter(|d| *d < 30) {
                hits.push((
                    Severity::High,
                    format!("Certificate {id} expires in {d} days"),
                    "Plan the renewal, or confirm automatic renewal will run.",
                ));
            }
            if mismatch {
                hits.push((
                    Severity::Medium,
                    format!("Endpoint {id}: presented certificate does not match"),
                    "Attach the expected certificate to the endpoint.",
                ));
            }
            if unattached {
                hits.push((
                    Severity::Info,
                    format!("Certificate {id} is not attached to anything"),
                    "Delete it if it is no longer needed.",
                ));
            }

            // One stable variant per certificate so the key never changes as days pass.
            if let Some((sev, title, step)) = hits.into_iter().next() {
                let s = format!("{title}.");
                out.push(draft(
                    ctx,
                    "05",
                    r,
                    "certificate",
                    sev,
                    (title, s, step),
                    facts.join(" "),
                ));
            }
        }
        out
    }
}
