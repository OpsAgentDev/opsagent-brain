use crate::ctx::{draft, short, Check, CheckCtx};
use opsagent_connectors::Capability;
use opsagent_core::finding::{FindingDraft, Severity};
use opsagent_core::resource::Provider;

pub struct InstanceHardening;

impl Check for InstanceHardening {
    fn id(&self) -> &'static str {
        "12"
    }
    fn supported(&self) -> &[Provider] {
        &[Provider::Aws, Provider::Fake]
    }
    fn required(&self) -> &[Capability] {
        &[Capability::Inventory]
    }

    fn run(&self, ctx: &CheckCtx) -> Vec<FindingDraft> {
        let mut out = vec![];
        for r in ctx.resources.iter().filter(|r| r.service() == "ec2") {
            let a = &r.attributes;
            let gone = matches!(a["state"].as_str(), Some("terminated" | "shutting-down"));
            // Unknown metadata options (null or absent) are never treated as IMDSv1.
            if gone
                || a["metadata_http_tokens"] != "optional"
                || a["metadata_http_endpoint"] != "enabled"
            {
                continue;
            }
            let public = a["has_public_ip"] == true;
            let sev = if public {
                Severity::High
            } else {
                Severity::Medium
            };
            let title = format!("Instance {} still allows IMDSv1", short(r));
            let s = format!(
                "{} answers metadata requests without a session token.",
                r.identity
            );
            let step = "IMDSv1 lets a server-side request forgery bug read the instance role's credentials. EC2 console > Instances > Actions > Instance settings > Modify instance metadata options > IMDSv2: Required, or `aws ec2 modify-instance-metadata-options --instance-id <instance-id> --http-tokens required`, and set the same in the launch template.";
            let ex = format!("http_tokens=optional http_endpoint=enabled has_public_ip={public}");
            out.push(draft(
                ctx,
                "12",
                r,
                "imdsv1_allowed",
                sev,
                (title, s, step),
                ex,
            ));
        }
        out
    }
}
