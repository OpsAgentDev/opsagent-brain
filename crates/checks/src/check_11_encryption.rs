use crate::ctx::{draft, Check, CheckCtx};
use opsagent_connectors::Capability;
use opsagent_core::finding::{FindingDraft, Severity};
use opsagent_core::resource::Provider;

pub struct EncryptionAtRest;

const STEP: &str =
    "Encryption cannot be switched on in place: snapshot, copy encrypted, restore, then cut over.";

impl Check for EncryptionAtRest {
    fn id(&self) -> &'static str {
        "11"
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
            let id = &r.identity;
            // Only an explicit `false` is a gap; a missing or null flag was not readable.
            if a["encrypted"] != false || ctx.unavailable.contains(r.service()) {
                continue;
            }
            let (variant, sev, what) = match r.service() {
                "rds" | "rds_cluster" if a["snapshot"] == true => {
                    ("unencrypted_snapshot", Severity::Low, "Snapshot")
                }
                "rds" | "rds_cluster" => ("unencrypted_database", Severity::High, "Database"),
                "ebs" => {
                    let sev = if a["attached"] == true {
                        Severity::Medium
                    } else {
                        Severity::Low
                    };
                    ("unencrypted_volume", sev, "Volume")
                }
                "ebs_snapshot" => ("unencrypted_snapshot", Severity::Low, "Snapshot"),
                _ => continue,
            };
            let title = format!("{what} {id} is not encrypted at rest");
            let s = format!("{title}.");
            let ex = match r.service() {
                "ebs" => format!("encrypted=false attached={}", a["attached"]),
                _ => "encrypted=false".into(),
            };
            out.push(draft(ctx, "11", r, variant, sev, (title, s, STEP), ex));
        }
        out
    }
}
