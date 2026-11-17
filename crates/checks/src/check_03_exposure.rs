use crate::ctx::{draft, short, Check, CheckCtx};
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

    // shortcut: ~76 lines, one match arm per exposure kind (snapshot, bucket, SG); split into a fn per service when a fourth appears.
    fn run(&self, ctx: &CheckCtx) -> Vec<FindingDraft> {
        let mut out = vec![];
        for r in ctx.resources {
            let a = &r.attributes;
            let (n, id) = (short(r), &r.identity);
            let (variant, sev, title, s, step, ex): (&str, _, String, String, &str, String) =
                match r.service() {
                    "rds" if a["snapshot"] == true && a["public"] == true => (
                        "public_snapshot",
                        Severity::Critical,
                        format!("Snapshot {n} is public"),
                        format!("Any AWS account can copy {id} and restore its data."),
                        "A public snapshot hands every AWS account a copy of the database. RDS console > Snapshots > Actions > Share snapshot > DB snapshot visibility: Private, or `aws rds modify-db-snapshot-attribute --db-snapshot-identifier <id> --attribute-name restore --values-to-remove all`.",
                        "snapshot=true public=true".into(),
                    ),
                    "rds" if a["publicly_accessible"] == true => (
                        "public_database",
                        Severity::Critical,
                        format!("Database {n} is publicly accessible"),
                        format!("{id} has an endpoint reachable from the internet."),
                        "A public endpoint lets anyone try to log in or exploit the engine. RDS console > Databases > Modify > Connectivity > Not publicly accessible, or `aws rds modify-db-instance --db-instance-identifier <id> --no-publicly-accessible --apply-immediately`.",
                        "publicly_accessible=true".into(),
                    ),
                    // AWS reports the policy as public, and the role cannot read the policy to see
                    // how much of the bucket: "" is "a prefix or all of it".
                    "s3" if a["block_public_access"] == false && a["public_policy_prefix"] == "" => (
                        "public_bucket",
                        Severity::High,
                        format!("Bucket {n} is public"),
                        format!("The policy of {id} allows public access and block public access is off."),
                        "Anyone on the internet can read what the policy exposes. Unless a public prefix is intended and holds nothing sensitive, S3 console > the bucket > Permissions > Block public access > Edit > turn all on, or `aws s3api put-public-access-block --bucket <bucket> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`.",
                        "block_public_access=false policy_status=public".into(),
                    ),
                    "s3" if a["block_public_access"] == false => {
                        let prefix = a["public_policy_prefix"].as_str().filter(|p| !p.is_empty());
                        (
                            "bucket_no_bpa",
                            Severity::Medium,
                            format!("Bucket {n} has no block-public-access"),
                            format!("Block public access is off for {id}."),
                            "Without it, one wrong policy or ACL makes the bucket public. Unless it is meant to be public, S3 console > the bucket > Permissions > Block public access > Edit > turn all on, or `aws s3api put-public-access-block --bucket <bucket> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`.",
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
                        let s = format!("{id} allows ports {ports:?} from any address.");
                        if to == "none" {
                            (
                                "sg_open_unused",
                                Severity::Low,
                                format!("Unused security group {n} is open to the world"),
                                s,
                                "Whatever the group is attached to later is exposed at once. Delete it: EC2 console > Security groups > Actions > Delete, or `aws ec2 delete-security-group --group-id <group-id>`.",
                                ex,
                            )
                        } else if ports.iter().any(|p| ADMIN_PORTS.contains(p)) {
                            ("sg_open_admin_port", Severity::Critical, format!("Security group {n} exposes an admin or database port to the world"), s,
                             "SSH, RDP and database ports open to the world are scanned and brute-forced within minutes. EC2 console > Security groups > Inbound rules > Edit, and replace 0.0.0.0/0 with your office or VPN range (`aws ec2 revoke-security-group-ingress` removes the open rule).", ex)
                        } else if to == "lb" && ports.iter().all(|p| *p == 80 || *p == 443) {
                            (
                                "sg_open_web_on_lb",
                                Severity::Info,
                                format!("Security group {n} serves web traffic on a load balancer"),
                                s,
                                "Web ports open on a load balancer are normal for a public site. No action is needed if it is public on purpose; otherwise narrow its inbound rules in EC2 console > Security groups.",
                                ex,
                            )
                        } else {
                            continue;
                        }
                    }
                    _ => continue,
                };
            out.push(draft(ctx, "03", r, variant, sev, (title, s, step), ex));
        }
        out
    }
}
