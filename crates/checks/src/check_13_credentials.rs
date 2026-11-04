use crate::ctx::{draft, Check, CheckCtx};
use opsagent_connectors::Capability;
use opsagent_core::finding::{FindingDraft, Severity};
use opsagent_core::resource::Provider;

pub struct CredentialDepth;

/// A key younger than this has had no time to be used yet.
const NEW_KEY_GRACE_DAYS: u64 = 7;
const STALE_PASSWORD_DAYS: u64 = 90;

impl Check for CredentialDepth {
    fn id(&self) -> &'static str {
        "13"
    }
    fn supported(&self) -> &[Provider] {
        &[Provider::Aws, Provider::Fake]
    }
    fn required(&self) -> &[Capability] {
        &[Capability::IamReport]
    }

    fn run(&self, ctx: &CheckCtx) -> Vec<FindingDraft> {
        let mut out = vec![];
        // A denied credential report leaves nothing to judge.
        if ctx.unavailable.contains("iam") {
            return out;
        }
        // Root is check 02's.
        let users = ctx
            .resources
            .iter()
            .filter(|r| r.service() == "iam" && r.attributes["root"] != true);
        for r in users {
            let a = &r.attributes;
            let mut add = |v: &str, sev, title: String, ex: String| {
                let s = format!("{title}.");
                let step = "Delete or rotate keys that were never used.";
                out.push(draft(ctx, "13", r, v, sev, (title, s, step), ex));
            };
            if let Some(age) = a["unused_key_age_days"]
                .as_u64()
                .filter(|d| *d >= NEW_KEY_GRACE_DAYS)
            {
                add(
                    "key_never_used",
                    Severity::Medium,
                    format!("An active access key of {} was never used", r.name),
                    format!("unused_key_age_days={age}"),
                );
            }
            if let Some(n) = a["access_keys_active"].as_u64().filter(|n| *n >= 2) {
                add(
                    "two_active_keys",
                    Severity::Low,
                    format!("{} has {n} active access keys", r.name),
                    format!("access_keys_active={n}"),
                );
            }
            if let Some(d) = a["console_last_used_days"]
                .as_u64()
                .filter(|d| a["console"] == true && *d > STALE_PASSWORD_DAYS)
            {
                add(
                    "stale_password",
                    Severity::Low,
                    format!("Console password of {} unused for {d} days", r.name),
                    format!("console_last_used_days={d}"),
                );
            }
        }
        out
    }
}
