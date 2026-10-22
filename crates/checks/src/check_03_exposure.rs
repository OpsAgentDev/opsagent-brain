use crate::ctx::{draft, svc, Check, CheckCtx};
use opsagent_connectors::Capability;
use opsagent_core::finding::{FindingDraft, Severity};
use opsagent_core::resource::Provider;

pub struct PublicExposure;

const ADMIN_PORTS: [u64; 7] = [22, 3389, 3306, 5432, 1433, 27017, 6379];

impl Check for PublicExposure {
    fn id(&self) -> &'static str {
        "03"
    }
    fn supported(&self) -> &[Provider] {
        &[Provider::Aws, Provider::Fake]
    }
    fn required(&self) -> &[Capability] {
        &[Capability::PublicAccess]
    }

    fn run(&self, ctx: &CheckCtx) -> Vec<FindingDraft> {
        let mut out = vec![];
        for r in ctx.resources {
            let a = &r.attributes;
            let id = &r.identity;
            let (variant, sev, title, step, ex): (&str, _, String, &str, String) = match svc(r) {
                "rds" if a["snapshot"] == true && a["public"] == true => (
                    "public_snapshot",
                    Severity::Critical,
                    format!("Snapshot {id} is public"),
                    "Make the snapshot private.",
                    "snapshot=true public=true".into(),
                ),
                "rds" if a["publicly_accessible"] == true => (
                    "public_database",
                    Severity::Critical,
                    format!("Database {id} is publicly accessible"),
                    "Disable public access and reach it through a private network.",
                    "publicly_accessible=true".into(),
                ),
                "s3" if a["block_public_access"] == false => {
                    let prefix = a["public_policy_prefix"].as_str().filter(|p| !p.is_empty());
                    (
                        "bucket_no_bpa",
                        Severity::Medium,
                        format!("Bucket {id} has no block-public-access"),
                        "Enable block public access unless the bucket is meant to be public.",
                        match prefix {
                            Some(p) => {
                                format!("block_public_access=false public_policy_prefix={p}")
                            }
                            None => "block_public_access=false".into(),
                        },
                    )
                }
                "sg" => {
                    let ports: Vec<u64> = a["open_world_ports"]
                        .as_array()
                        .map(|v| v.iter().filter_map(|p| p.as_u64()).collect())
                        .unwrap_or_default();
                    if ports.is_empty() {
                        continue;
                    }
                    let to = a["attached_to"].as_str().unwrap_or("");
                    let ex = format!("open_world_ports={ports:?} attached_to={to}");
                    if to == "none" {
                        (
                            "sg_open_unused",
                            Severity::Low,
                            format!("Unused security group {id} is open to the world"),
                            "Delete the group or close the open ports.",
                            ex,
                        )
                    } else if ports.iter().any(|p| ADMIN_PORTS.contains(p)) {
                        ("sg_open_admin_port", Severity::Critical, format!("Security group {id} exposes an admin or database port to the world"),
                         "Restrict the source to known addresses or a VPN.", ex)
                    } else if to == "lb" && ports.iter().all(|p| *p == 80 || *p == 443) {
                        (
                            "sg_open_web_on_lb",
                            Severity::Info,
                            format!("Security group {id} serves web traffic on a load balancer"),
                            "No action needed if this load balancer is public on purpose.",
                            ex,
                        )
                    } else {
                        continue;
                    }
                }
                _ => continue,
            };
            let s = format!("{title}.");
            out.push(draft(ctx, "03", r, variant, sev, (title, s, step), ex));
        }
        out
    }
}
