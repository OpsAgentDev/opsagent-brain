use crate::ctx::{draft, Check, CheckCtx};
use opsagent_connectors::Capability;
use opsagent_core::finding::{FindingDraft, Severity};
use opsagent_core::resource::Provider;

pub struct IamHygiene;

impl Check for IamHygiene {
    fn id(&self) -> &'static str {
        "02"
    }
    fn supported(&self) -> &[Provider] {
        &[Provider::Aws, Provider::Fake]
    }
    fn required(&self) -> &[Capability] {
        &[Capability::IamReport]
    }

    // shortcut: ~52 lines, one match arm per IAM variant; split per variant when a fourth appears.
    fn run(&self, ctx: &CheckCtx) -> Vec<FindingDraft> {
        let mut out = vec![];
        for r in ctx.resources.iter().filter(|r| r.service() == "iam") {
            let a = &r.attributes;
            let mut add = |v: &str, sev, title: String, step: &str, ex: String| {
                let s = format!("{title}.");
                out.push(draft(ctx, "02", r, v, sev, (title, s, step), ex));
            };
            if a["root"] == true {
                let days = a["console_last_used_days"].as_u64();
                let keys = a["access_keys_active"].as_u64().unwrap_or(0);
                if days.is_some_and(|d| d <= 30) || keys > 0 {
                    add(
                        "root_used",
                        Severity::Critical,
                        "Root account in use".into(),
                        "Stop using root, delete its access keys, and use an IAM role.",
                        format!("console_last_used_days={days:?} access_keys_active={keys}"),
                    );
                }
                continue;
            }
            if a["key_age_days"].as_u64().is_some_and(|d| d > 90) {
                add(
                    "key_over_90d",
                    Severity::Medium,
                    format!("Access key of {} is over 90 days old", r.identity),
                    "Rotate the key and delete the old one.",
                    format!("key_age_days={}", a["key_age_days"]),
                );
            }
            if a["console"] == true && a["mfa"] == false {
                add(
                    "no_mfa",
                    Severity::Medium,
                    format!("{} has console access without MFA", r.identity),
                    "Require an MFA device for this user.",
                    "console=true mfa=false".into(),
                );
            }
            if a["admin"] == true {
                add(
                    "admin_user",
                    Severity::High,
                    format!("{} has administrator access", r.identity),
                    "Replace the admin policy with scoped permissions or a role.",
                    "admin=true".into(),
                );
            }
        }
        out
    }
}
