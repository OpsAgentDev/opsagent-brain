use crate::ctx::{draft, short, Check, CheckCtx};
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
            let (n, id) = (short(r), &r.identity);
            let until = a["not_after"].as_str().unwrap_or("unknown");
            // Candidates in worst-first order; the first is the one finding emitted.
            let mut hits: Vec<(Severity, String, String, &str)> = vec![];
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
                        format!("Certificate {n} expired {} days ago", -d)
                    } else {
                        format!("Certificate {n} expires in {d} days")
                    },
                    format!("{id} is valid until {until}."),
                    "An expired certificate makes browsers and clients refuse the connection. Renew or replace it now: ACM console > Request certificate (or Reimport for an imported one), then select it on the load balancer listener or distribution.",
                ));
            }
            if failed {
                hits.push((
                    Severity::High,
                    format!("Certificate {n}: managed renewal failed"),
                    format!("ACM could not renew {id}; it is valid until {until}."),
                    "ACM renews only while it can validate the domain, so this certificate will expire. ACM console > Certificates > the certificate: add the CNAME validation record shown there to your DNS, or approve the validation email.",
                ));
            }
            if let Some(d) = days.filter(|d| *d < 30) {
                hits.push((
                    Severity::High,
                    format!("Certificate {n} expires in {d} days"),
                    format!("{id} is valid until {until}."),
                    "A missed renewal takes the site down on the expiry date. For an ACM-issued certificate check Renewal status in ACM console > Certificates; for an imported one, import the renewed certificate before then (`aws acm import-certificate --certificate-arn <arn>`).",
                ));
            }
            if mismatch {
                hits.push((
                    Severity::Medium,
                    format!("Endpoint {n}: presented certificate does not match"),
                    format!("{id} serves a different certificate than the one expected."),
                    "Clients get a certificate other than the one you manage, which may be stale or wrong. EC2 console > Load balancers > Listeners > Edit, and select the expected certificate.",
                ));
            }
            if unattached {
                hits.push((
                    Severity::Info,
                    format!("Certificate {n} is not attached to anything"),
                    format!("No load balancer or distribution uses {id}."),
                    "An unused certificate costs nothing but clutters the inventory and can be attached by mistake. Delete it if no longer needed: ACM console > Certificates > Delete, or `aws acm delete-certificate --certificate-arn <arn>`.",
                ));
            }

            // One stable variant per certificate so the key never changes as days pass.
            if let Some((sev, title, s, step)) = hits.into_iter().next() {
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
