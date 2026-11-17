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
            let id = &r.identity;
            let mut add = |v: &str, sev, (title, s, step): (String, String, &str), ex: String| {
                out.push(draft(ctx, "13", r, v, sev, (title, s, step), ex));
            };
            if let Some(age) = a["unused_key_age_days"]
                .as_u64()
                .filter(|d| *d >= NEW_KEY_GRACE_DAYS)
            {
                add(
                    "key_never_used",
                    Severity::Medium,
                    (format!("An active access key of {} was never used", r.name),
                    format!("User {id} has had an active, never-used access key for {age} days."),
                    "An unused key is a live credential nobody watches. Delete it: IAM console > Users > the user > Security credentials > Access keys, or `aws iam delete-access-key --user-name <user> --access-key-id <key-id>`."),
                    format!("unused_key_age_days={age}"),
                );
            }
            if let Some(n) = a["access_keys_active"].as_u64().filter(|n| *n >= 2) {
                add(
                    "two_active_keys",
                    Severity::Low,
                    (format!("{} has {n} active access keys", r.name),
                    format!("User {id} has {n} keys active at once."),
                    "Two live keys usually mean a rotation was never finished, doubling what can leak. Delete the one no longer used: IAM console > Users > the user > Security credentials, or `aws iam delete-access-key`."),
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
                    (format!("Console password of {} unused for {d} days", r.name),
                    format!("User {id} still has a console password it does not use."),
                    "A password nobody uses can still be guessed or phished. Remove it: IAM console > Users > the user > Security credentials > Console sign-in > Disable, or `aws iam delete-login-profile --user-name <user>`."),
                    format!("console_last_used_days={d}"),
                );
            }
        }
        out
    }
}
