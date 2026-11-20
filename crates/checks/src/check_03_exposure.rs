use crate::ctx::{draft, short, Check, CheckCtx};
use opsagent_connectors::Capability;
use opsagent_core::finding::{FindingDraft, Severity};
use opsagent_core::resource::Provider;

pub struct PublicExposure;

/// SSH, RDP, databases, caches, Elasticsearch, Kibana and the Docker API.
const ADMIN_PORTS: [u64; 11] = [
    22, 3389, 3306, 5432, 1433, 27017, 6379, 9200, 5601, 11211, 2375,
];

/// Snapshot kinds that can be shared with every AWS account: (service, variant, label, what a
/// copy gives, how to make it private). Each is critical, and a 15-minute watch scan covers all.
const PUBLIC_SNAPSHOTS: [(&str, &str, &str, &str, &str); 3] = [
    (
        "rds",
        "public_snapshot",
        "Snapshot",
        "restore its data",
        "A public snapshot hands every AWS account a copy of the database. RDS console > Snapshots > Actions > Share snapshot > DB snapshot visibility: Private, or `aws rds modify-db-snapshot-attribute --db-snapshot-identifier <id> --attribute-name restore --values-to-remove all`.",
    ),
    (
        "rds_cluster_snapshot",
        "public_cluster_snapshot",
        "Cluster snapshot",
        "restore its data",
        "A public cluster snapshot hands every AWS account a copy of the database. RDS console > Snapshots > Manual > the snapshot > Actions > Share snapshot > DB snapshot visibility: Private, or `aws rds modify-db-cluster-snapshot-attribute --db-cluster-snapshot-identifier <id> --attribute-name restore --values-to-remove all`.",
    ),
    (
        "ebs_snapshot",
        "public_disk_snapshot",
        "Disk snapshot",
        "create a volume from its data",
        "A public disk snapshot hands every AWS account a copy of the disk. EC2 console > Snapshots > Actions > Modify permissions > Private, or `aws ec2 modify-snapshot-attribute --snapshot-id <snapshot-id> --attribute createVolumePermission --operation-type remove --group-names all`.",
    ),
];

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

    // shortcut: ~75 lines, one match arm per exposure kind (database, bucket, SG; snapshots are a table); split into a fn per service when another appears.
    fn run(&self, ctx: &CheckCtx) -> Vec<FindingDraft> {
        let mut out = vec![];
        for r in ctx.resources {
            let a = &r.attributes;
            let (n, id) = (short(r), &r.identity);
            let snapshot = PUBLIC_SNAPSHOTS.iter().find(|k| k.0 == r.service());
            if let (Some(&(_, variant, label, gives, step)), true) = (snapshot, a["public"] == true)
            {
                let (title, s) = (
                    format!("{label} {n} is public"),
                    format!("Any AWS account can copy {id} and {gives}."),
                );
                let ex = "snapshot=true public=true".into();
                out.push(draft(
                    ctx,
                    "03",
                    r,
                    variant,
                    Severity::Critical,
                    (title, s, step),
                    ex,
                ));
                continue;
            }
            let (variant, sev, title, s, step, ex): (&str, _, String, String, &str, String) =
                match r.service() {
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
