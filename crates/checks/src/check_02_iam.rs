use crate::ctx::{draft, short, Check, CheckCtx};
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

    // shortcut: ~65 lines, one match arm per IAM variant; split per variant when a fourth appears.
    fn run(&self, ctx: &CheckCtx) -> Vec<FindingDraft> {
        let mut out = vec![];
        for r in ctx.resources.iter().filter(|r| r.service() == "iam") {
            let a = &r.attributes;
            let (n, id) = (short(r), &r.identity);
            let mut add = |v: &str, sev, (title, s, step): (String, String, &str), ex: String| {
                out.push(draft(ctx, "02", r, v, sev, (title, s, step), ex));
            };
            if a["root"] == true {
                let days = a["console_last_used_days"].as_u64();
                let keys = a["access_keys_active"].as_u64().unwrap_or(0);
                if days.is_some_and(|d| d <= 30) || keys > 0 {
                    add(
                        "root_used",
                        Severity::Critical,
                        ("Root account in use".into(),
                        "The root user signed in within the last 30 days or has an active access key.".into(),
                        "No policy can limit root, so one leaked root credential is full control of the account. Sign in as root, open the account menu > Security credentials, delete its access keys, and use an IAM role for daily work."),
                        format!("console_last_used_days={days:?} access_keys_active={keys}"),
                    );
                }
                // Centralised root access: no password and no keys leave nothing to protect with MFA.
                let no_credentials = a["password"] == false && keys == 0;
                if a["mfa"] == false && !no_credentials {
                    add(
                        "root_no_mfa",
                        Severity::High,
                        ("Root account has no MFA".into(),
                        "The root user can sign in with a password alone.".into(),
                        "Anyone with the root password gets full control of the account. Sign in as root and open the account menu > Security credentials > Assign MFA device, or remove root credentials centrally from the management account (IAM > Root access management)."),
                        "root=true mfa=false".into(),
                    );
                }
                continue;
            }
            if a["key_age_days"].as_u64().is_some_and(|d| d > 90) {
                add(
                    "key_over_90d",
                    Severity::Medium,
                    (format!("Access key of {n} is over 90 days old"),
                    format!("User {id} has an active access key last rotated {} days ago.", a["key_age_days"]),
                    "The older a key, the more places it may have leaked to. Create a new key, move the app to it, then delete the old one: IAM console > Users > the user > Security credentials, or `aws iam create-access-key` then `aws iam delete-access-key`."),
                    format!("key_age_days={}", a["key_age_days"]),
                );
            }
            if a["console"] == true && a["mfa"] == false {
                add(
                    "no_mfa",
                    Severity::Medium,
                    (format!("{n} has console access without MFA"),
                    format!("User {id} can sign in to the console with a password alone."),
                    "A phished or reused password is enough to sign in. Assign a device in IAM console > Users > the user > Security credentials > Assign MFA device."),
                    "console=true mfa=false".into(),
                );
            }
            // shortcut: `admin` covers AdministratorAccess attached to the user only (the read role
            // has no group or inline policy reads); widen with role template v2.
            if a["admin"] == true {
                add(
                    "admin_user",
                    Severity::High,
                    (format!("{n} has administrator access"),
                    format!("User {id} has the AdministratorAccess policy attached."),
                    "A leaked key or password of this user can change anything in the account. Grant only what it needs or have it assume a role: IAM console > Users > the user > Permissions > remove AdministratorAccess, or `aws iam detach-user-policy --user-name <user> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess`."),
                    "admin=true".into(),
                );
            }
        }
        out
    }
}
