mod common;
use common::*;
use opsagent_checks::check_03_exposure::PublicExposure;
use opsagent_core::finding::Severity::*;
use opsagent_core::resource::{Provider, Resource, ResourceKind};

#[tokio::test]
async fn noisy_exact_set() {
    let (r, c) = load("noisy").await;
    let got = set(&run(&PublicExposure, &r, &c));
    let mut want = vec![
        t("snap-public", "public_snapshot", Critical),
        t("bucket-open", "bucket_no_bpa", Medium),
        t("sg-ssh", "sg_open_admin_port", Critical),
        t("sg-web", "sg_open_web_on_lb", Info),
        t("sg-db", "sg_open_unused", Low),
    ];
    want.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    assert_eq!(got, want);
}

#[tokio::test]
async fn clean_is_empty() {
    let (r, c) = load("clean").await;
    assert!(run(&PublicExposure, &r, &c).is_empty());
}

fn res(id: &str, attrs: serde_json::Value) -> Resource {
    Resource {
        provider: Provider::Aws,
        account: "1".into(),
        region: "r".into(),
        kind: ResourceKind::Database,
        identity: id.into(),
        name: id.into(),
        tags: Default::default(),
        attributes: attrs,
        observed_at: "2026-10-01T00:00:00Z".parse().unwrap(),
    }
}

#[test]
fn public_db_and_prefix_bucket() {
    let rs = [
        res(
            "db",
            serde_json::json!({"service":"rds","publicly_accessible":true,"backup_retention_days":1}),
        ),
        res(
            "b",
            serde_json::json!({"service":"s3","block_public_access":false,"public_policy_prefix":"logs/"}),
        ),
    ];
    let d = run(&PublicExposure, &rs, &[]);
    assert_eq!(
        set(&d),
        vec![
            t("b", "bucket_no_bpa", Medium),
            t("db", "public_database", Critical)
        ]
    );
    assert!(d
        .iter()
        .find(|d| d.key.variant == "bucket_no_bpa")
        .unwrap()
        .evidence[0]
        .excerpt
        .contains("logs/"));
}

#[test]
fn search_cache_and_docker_ports_are_admin_ports() {
    let sg = |ports: &[u16]| serde_json::json!({"service":"sg","open_world_ports":ports,"attached_to":"instance"});
    let rs = [
        res("sg-es", sg(&[9200])),
        res("sg-kibana", sg(&[443, 5601])),
        res("sg-memcached", sg(&[11211])),
        res("sg-docker", sg(&[2375])),
        // Not an admin port: an app port alone is not flagged.
        res("sg-app", sg(&[8080])),
    ];
    assert_eq!(
        set(&run(&PublicExposure, &rs, &[])),
        vec![
            t("sg-docker", "sg_open_admin_port", Critical),
            t("sg-es", "sg_open_admin_port", Critical),
            t("sg-kibana", "sg_open_admin_port", Critical),
            t("sg-memcached", "sg_open_admin_port", Critical),
        ]
    );
}

#[test]
fn public_bucket_and_group_on_a_task() {
    let sg = |to: &str, ports: &[u16]| serde_json::json!({"service":"sg","open_world_ports":ports,"attached_to":to});
    let s3 = |bpa: bool, prefix: Option<&str>| serde_json::json!({"service":"s3","block_public_access":bpa,"public_policy_prefix":prefix});
    let rs = [
        res("b-public", s3(false, Some(""))),
        res("b-private", s3(false, None)),
        // Public by policy, but block-public-access overrides it.
        res("b-blocked", s3(true, Some(""))),
        res("sg-task-db", sg("other", &[6379])),
        res("sg-task-web", sg("other", &[443])),
    ];
    assert_eq!(
        set(&run(&PublicExposure, &rs, &[])),
        vec![
            t("b-private", "bucket_no_bpa", Medium),
            t("b-public", "public_bucket", High),
            t("sg-task-db", "sg_open_admin_port", Critical),
        ]
    );
}

#[test]
fn public_cluster_and_disk_snapshots_are_critical_like_instance_snapshots() {
    let snap = |service: &str, public: serde_json::Value| serde_json::json!({"service": service, "public": public, "encrypted": true});
    let rs = [
        res("c-open", snap("rds_cluster_snapshot", true.into())),
        res("c-private", snap("rds_cluster_snapshot", false.into())),
        // Read without the sharing permission: unknown, never public.
        res(
            "c-unknown",
            snap("rds_cluster_snapshot", serde_json::Value::Null),
        ),
        res("d-open", snap("ebs_snapshot", true.into())),
        res("d-private", snap("ebs_snapshot", false.into())),
        res("d-unknown", snap("ebs_snapshot", serde_json::Value::Null)),
    ];
    let d = run(&PublicExposure, &rs, &[]);
    assert_eq!(
        set(&d),
        vec![
            t("c-open", "public_cluster_snapshot", Critical),
            t("d-open", "public_disk_snapshot", Critical),
        ]
    );
    let f = |v: &str| d.iter().find(|d| d.key.variant == v).unwrap();
    assert_eq!(
        f("public_cluster_snapshot").title,
        "Cluster snapshot c-open is public"
    );
    assert_eq!(
        f("public_disk_snapshot").title,
        "Disk snapshot d-open is public"
    );
    assert_eq!(
        f("public_disk_snapshot").summary,
        "Any AWS account can copy d-open and create a volume from its data."
    );
    assert!(f("public_cluster_snapshot")
        .next_step
        .contains("modify-db-cluster-snapshot-attribute"));
    assert!(f("public_disk_snapshot")
        .next_step
        .contains("modify-snapshot-attribute"));
}
