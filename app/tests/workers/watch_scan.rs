//! `watch_scan`: the 15-minute subset of the full scan (urgent-alerts spec). It opens findings
//! from `sg`, `rds` and `cloudtrail` only, and never resolves, marks gone or waits on a full scan.
use std::collections::BTreeSet;

use async_trait::async_trait;
use opsagent_brain::{
    actions::runs::FullScan,
    adapters::db::ledger_storage::PgStorage,
    models::_entities::{connections, findings, resource_history, resources, runs},
};
use opsagent_checks::{Check, CheckCtx};
use opsagent_connectors::{
    fake::FakeConnector, Capability, Connector, ConnectorError, CostRow, Credentials,
    InventoryResult, MetricPoint, MetricQuery, Scope, SimulationResult, VerifyOutcome,
};
use opsagent_core::{
    finding::{FindingDraft, FindingKey, Severity},
    resource::Provider,
    run::RunKey,
};
use opsagent_ledger::{lease, RunChunkedOptions, Storage};
use sea_orm::entity::prelude::*;
use serial_test::serial;
use uuid::Uuid;

use super::full_scan::{fixture, noisy, scan, without_snapshot};
use crate::requests::support::*;

async fn connection(req: &axum_test::TestServer, ctx: &TestApp) -> Uuid {
    connected(req, ctx, "o@example.com", "noisy").await.2
}

fn watch(ctx: &TestApp, k: impl Connector + 'static) -> FullScan {
    let actions = actions(ctx).unwrap();
    (actions.runs.watch_scan.clone()).with_connector(std::sync::Arc::new(k))
}

/// Runs one watch scan for the connection; returns the run row.
async fn watch_run(ctx: &TestApp, conn: Uuid, n: i64, ws: &FullScan) -> runs::Model {
    let at = chrono::DateTime::from_timestamp(1_900_000_000 + n * 60, 0).unwrap();
    watch_run_at(ctx, conn, at, ws).await
}

/// `watch_run` for slot `at`.
async fn watch_run_at(
    ctx: &TestApp,
    conn: Uuid,
    at: chrono::DateTime<chrono::Utc>,
    ws: &FullScan,
) -> runs::Model {
    let c = connections::Entity::find_by_id(conn)
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap();
    let run = PgStorage::new(ctx.db.clone())
        .create_run(RunKey {
            organisation_id: Some(c.organisation_id),
            connection_id: Some(conn),
            job_type: "watch_scan".into(),
            scheduled_at: at,
        })
        .await
        .unwrap()
        .run
        .id;
    ws.run(run, RunChunkedOptions::default()).await.unwrap();
    runs::Entity::find_by_id(run)
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap()
}

async fn all_findings(ctx: &TestApp, conn: Uuid) -> Vec<findings::Model> {
    findings::Entity::find()
        .filter(findings::Column::ConnectionId.eq(conn))
        .all(&ctx.db)
        .await
        .unwrap()
}

async fn finding(ctx: &TestApp, conn: Uuid, identity: &str) -> Option<findings::Model> {
    let all = all_findings(ctx, conn).await;
    all.into_iter()
        .find(|f| f.resource_identity.ends_with(identity))
}

fn outcome(r: &runs::Model) -> (&str, Option<&str>) {
    (r.status.as_str(), r.partial_reason.as_deref())
}

#[tokio::test]
#[serial]
async fn watch_scan_opens_public_snapshot_without_resolving_others() {
    serve(|req, ctx| async move {
        let conn = connection(&req, &ctx).await;
        scan(&ctx, conn, 0, &without_snapshot()).await;
        assert!(finding(&ctx, conn, "snap-public").await.is_none());
        let open_before: BTreeSet<(Uuid, Option<Uuid>, i32)> = all_findings(&ctx, conn)
            .await
            .into_iter()
            .filter(|f| f.status == "open")
            .map(|f| (f.id, f.last_seen_run_id, f.stable_runs))
            .collect();
        assert!(finding(&ctx, conn, "user-admin").await.is_some());
        assert!(finding(&ctx, conn, "bucket-open").await.is_some());

        let r = watch_run(&ctx, conn, 0, &watch(&ctx, noisy())).await;
        assert_eq!(outcome(&r), ("done", None));
        let snap = finding(&ctx, conn, "snap-public").await.unwrap();
        assert_eq!(
            (
                snap.status.as_str(),
                snap.severity.as_str(),
                snap.variant.as_str()
            ),
            ("open", "critical", "public_snapshot")
        );
        // The IAM and bucket findings, and every other finding, stay open; already-open ones
        // (the open SSH group too) are left to the full scan, counters untouched.
        for (id, seen, stable) in open_before {
            let f = findings::Entity::find_by_id(id)
                .one(&ctx.db)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(f.status, "open", "{}", f.resource_identity);
            assert_eq!((f.last_seen_run_id, f.stable_runs), (seen, stable));
        }
        // No posture in a watch run's stats: the score is the full scan's.
        assert!(r.checkpoint["stats"].get("score").is_none());
    })
    .await;
}

#[tokio::test]
#[serial]
async fn watch_scan_never_marks_resources_gone() {
    serve(|req, ctx| async move {
        let conn = connection(&req, &ctx).await;
        scan(&ctx, conn, 0, &noisy()).await;
        // Between watch scans the SSH group and the snapshot are deleted.
        let churned = fixture(|v| {
            v["resources"]
                .as_array_mut()
                .unwrap()
                .retain(|r| r["identity"] != "sg-ssh" && r["identity"] != "snap-public")
        });
        let r = watch_run(&ctx, conn, 0, &watch(&ctx, churned)).await;
        assert_eq!(outcome(&r), ("done", None));
        for id in ["sg-ssh", "snap-public", "i-idle", "bucket-open"] {
            let res = resources::Entity::find()
                .filter(resources::Column::ConnectionId.eq(conn))
                .filter(resources::Column::Identity.eq(id))
                .one(&ctx.db)
                .await
                .unwrap()
                .unwrap();
            assert!(res.gone_at.is_none(), "{id} marked gone");
        }
        for f in all_findings(&ctx, conn).await {
            assert_eq!(f.status, "open", "{}", f.resource_identity);
        }
    })
    .await;
}

#[tokio::test]
#[serial]
async fn watch_scan_leaves_no_resource_history() {
    serve(|req, ctx| async move {
        let conn = connection(&req, &ctx).await;
        let full = scan(&ctx, conn, 0, &noisy()).await;
        let rows = |run: Uuid| {
            let db = ctx.db.clone();
            async move {
                resource_history::Entity::find()
                    .filter(resource_history::Column::RunId.eq(run))
                    .count(&db)
                    .await
                    .unwrap()
            }
        };
        let before = rows(full).await;
        assert!(before > 0);
        let r = watch_run(&ctx, conn, 0, &watch(&ctx, noisy())).await;
        assert_eq!(outcome(&r), ("done", None));
        assert_eq!(rows(r.id).await, 0);
        assert_eq!(rows(full).await, before);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn watch_scan_skips_while_full_scan_leased() {
    serve(|req, ctx| async move {
        let conn = connection(&req, &ctx).await;
        scan(&ctx, conn, 0, &noisy()).await;
        let ttl = std::time::Duration::from_secs(60);
        for job in ["full_scan", "watch_scan"] {
            let key = format!("lease:conn:{conn}:{job}");
            assert!(lease::claim(&ctx.redis(), &key, "other-run", ttl)
                .await
                .unwrap());
            let n = i64::from(job == "watch_scan");
            let r = watch_run(&ctx, conn, n, &watch(&ctx, noisy())).await;
            assert_eq!(outcome(&r), ("skipped", Some("overlap")), "{job}");
            lease::unclaim(&ctx.redis(), &key, "other-run").await;
        }
        let r = watch_run(&ctx, conn, 2, &watch(&ctx, noisy())).await;
        assert_eq!(outcome(&r), ("done", None));
    })
    .await;
}

#[tokio::test]
#[serial]
async fn watch_scan_waits_for_first_full_scan() {
    serve(|req, ctx| async move {
        let conn = connection(&req, &ctx).await;
        let r = watch_run(&ctx, conn, 0, &watch(&ctx, noisy())).await;
        assert_eq!(outcome(&r), ("skipped", Some("no_baseline")));
        assert!(all_findings(&ctx, conn).await.is_empty());
    })
    .await;
}

/// `noisy` whose scoped inventory call for `service` fails.
#[derive(Clone)]
struct Failing {
    inner: FakeConnector,
    service: &'static str,
}

#[async_trait]
impl Connector for Failing {
    fn provider(&self) -> Provider {
        self.inner.provider()
    }
    fn capabilities(&self) -> BTreeSet<Capability> {
        self.inner.capabilities()
    }
    async fn verify(&self, c: &Credentials) -> opsagent_connectors::Result<VerifyOutcome> {
        self.inner.verify(c).await
    }
    async fn inventory(
        &self,
        c: &Credentials,
        s: &Scope,
    ) -> opsagent_connectors::Result<InventoryResult> {
        if s.services == [self.service] {
            return Err(ConnectorError::Api {
                code: Some("ServiceUnavailable".into()),
                message: "down".into(),
            });
        }
        self.inner.inventory(c, s).await
    }
    async fn cost_daily(
        &self,
        c: &Credentials,
        d: u32,
    ) -> opsagent_connectors::Result<Vec<CostRow>> {
        self.inner.cost_daily(c, d).await
    }
    async fn metrics(
        &self,
        c: &Credentials,
        q: MetricQuery,
    ) -> opsagent_connectors::Result<Vec<MetricPoint>> {
        self.inner.metrics(c, q).await
    }
    async fn simulate_restore(
        &self,
        c: &Credentials,
        role: &str,
    ) -> opsagent_connectors::Result<SimulationResult> {
        self.inner.simulate_restore(c, role).await
    }
}

/// `noisy` that claims the full-scan lease on its first scoped (chunk) inventory call: a full
/// scan starts after the watch passed its start gate.
#[derive(Clone)]
struct FullScanStarts {
    inner: FakeConnector,
    redis: opsagent_ledger::redis::Client,
    key: String,
}

#[async_trait]
impl Connector for FullScanStarts {
    fn provider(&self) -> Provider {
        self.inner.provider()
    }
    fn capabilities(&self) -> BTreeSet<Capability> {
        self.inner.capabilities()
    }
    async fn verify(&self, c: &Credentials) -> opsagent_connectors::Result<VerifyOutcome> {
        self.inner.verify(c).await
    }
    async fn inventory(
        &self,
        c: &Credentials,
        s: &Scope,
    ) -> opsagent_connectors::Result<InventoryResult> {
        if s.services.len() == 1 {
            let ttl = std::time::Duration::from_secs(60);
            lease::claim(&self.redis, &self.key, "full-run", ttl)
                .await
                .unwrap();
        }
        self.inner.inventory(c, s).await
    }
    async fn cost_daily(
        &self,
        c: &Credentials,
        d: u32,
    ) -> opsagent_connectors::Result<Vec<CostRow>> {
        self.inner.cost_daily(c, d).await
    }
    async fn metrics(
        &self,
        c: &Credentials,
        q: MetricQuery,
    ) -> opsagent_connectors::Result<Vec<MetricPoint>> {
        self.inner.metrics(c, q).await
    }
    async fn simulate_restore(
        &self,
        c: &Credentials,
        role: &str,
    ) -> opsagent_connectors::Result<SimulationResult> {
        self.inner.simulate_restore(c, role).await
    }
}

#[tokio::test]
#[serial]
async fn watch_finalize_skips_when_full_scan_started_mid_run() {
    serve(|req, ctx| async move {
        let conn = connection(&req, &ctx).await;
        scan(&ctx, conn, 0, &without_snapshot()).await;
        let before = all_findings(&ctx, conn).await.len();
        let key = format!("lease:conn:{conn}:full_scan");
        let k = FullScanStarts {
            inner: noisy(),
            redis: ctx.redis(),
            key: key.clone(),
        };
        let r = watch_run(&ctx, conn, 0, &watch(&ctx, k)).await;
        assert_eq!(outcome(&r), ("skipped", Some("overlap")));
        assert!(finding(&ctx, conn, "snap-public").await.is_none());
        assert_eq!(all_findings(&ctx, conn).await.len(), before);
        let history = resource_history::Entity::find()
            .filter(resource_history::Column::RunId.eq(r.id))
            .count(&ctx.db)
            .await
            .unwrap();
        assert_eq!(history, 0);
        lease::unclaim(&ctx.redis(), &key, "full-run").await;
    })
    .await;
}

#[tokio::test]
#[serial]
async fn watch_scan_skips_check_with_failed_chunk() {
    serve(|req, ctx| async move {
        let conn = connection(&req, &ctx).await;
        // Baseline with a healthy trail, no public snapshot and no open SSH group.
        let healthy = |v: &mut serde_json::Value| {
            for r in v["resources"].as_array_mut().unwrap() {
                if r["identity"] == "cloudtrail-main" {
                    r["attributes"]["bucket_writable"] = true.into();
                }
            }
        };
        let clean = fixture(|v| {
            healthy(v);
            v["resources"]
                .as_array_mut()
                .unwrap()
                .retain(|r| r["identity"] != "snap-public" && r["identity"] != "sg-ssh");
        });
        scan(&ctx, conn, 0, &clean).await;
        let trail_off = |ctx: TestApp| async move {
            all_findings(&ctx, conn)
                .await
                .into_iter()
                .any(|f| f.variant == "trail_effectively_off")
        };
        assert!(!trail_off(ctx.clone()).await);

        // SSH is open to the world, but the rds chunk fails: all of check 03 is skipped.
        let k = Failing {
            inner: fixture(healthy),
            service: "rds",
        };
        let r = watch_run(&ctx, conn, 0, &watch(&ctx, k)).await;
        assert_eq!(r.status, "partial");
        assert_eq!(
            r.checkpoint["stats"]["skipped_checks"],
            serde_json::json!(["03"])
        );
        assert!(finding(&ctx, conn, "sg-ssh").await.is_none());

        // The trail is off, but its chunk fails: no trail-off finding.
        let k = Failing {
            inner: noisy(),
            service: "cloudtrail",
        };
        let r = watch_run(&ctx, conn, 1, &watch(&ctx, k)).await;
        assert_eq!(r.status, "partial");
        assert!(!trail_off(ctx.clone()).await);
        assert!(finding(&ctx, conn, "sg-ssh").await.is_some());

        // With every chunk read, the next watch opens it.
        watch_run(&ctx, conn, 2, &watch(&ctx, noisy())).await;
        assert!(trail_off(ctx.clone()).await);
    })
    .await;
}

/// Test-only check posing as check 03 with one allowed and one disallowed critical.
struct Impostor;
impl Check for Impostor {
    fn id(&self) -> &'static str {
        "03"
    }
    fn supported(&self) -> &[Provider] {
        &[Provider::Fake]
    }
    fn required(&self) -> &[Capability] {
        &[]
    }
    fn run(&self, cx: &CheckCtx) -> Vec<FindingDraft> {
        ["bucket_no_bpa", "sg_open_admin_port"]
            .into_iter()
            .map(|variant| FindingDraft {
                key: FindingKey {
                    connection_id: cx.connection_id,
                    check_id: "03".into(),
                    resource_identity: "impostor".into(),
                    variant: variant.into(),
                },
                severity: Severity::Critical,
                title: "t".into(),
                summary: "s".into(),
                next_step: "n".into(),
                cost_monthly_usd: None,
                evidence: vec![],
            })
            .collect()
    }
}

fn with_impostor() -> Vec<Box<dyn Check>> {
    let mut v = opsagent_checks::all();
    v.push(Box::new(Impostor));
    v
}

#[tokio::test]
#[serial]
async fn watch_drafts_outside_allowlist_dropped() {
    serve(|req, ctx| async move {
        let conn = connection(&req, &ctx).await;
        scan(&ctx, conn, 0, &noisy()).await;
        let ws = watch(&ctx, noisy()).with_checks(with_impostor);
        watch_run(&ctx, conn, 0, &ws).await;
        let got: Vec<String> = all_findings(&ctx, conn)
            .await
            .into_iter()
            .filter(|f| f.resource_identity == "impostor")
            .map(|f| f.variant)
            .collect();
        assert_eq!(got, ["sg_open_admin_port"]);
    })
    .await;
}

/// The connection's `deliver_alert` runs, by slot.
async fn deliveries(ctx: &TestApp, conn: Uuid) -> Vec<runs::Model> {
    let mut v = runs::Entity::find()
        .filter(runs::Column::ConnectionId.eq(conn))
        .filter(runs::Column::JobType.eq("deliver_alert"))
        .all(&ctx.db)
        .await
        .unwrap();
    v.sort_by_key(|r| r.scheduled_at);
    v
}

#[tokio::test]
#[serial]
async fn watch_scan_enqueues_a_delivery_only_for_unalerted_criticals() {
    serve(|req, ctx| async move {
        let conn = connection(&req, &ctx).await;
        scan(&ctx, conn, 0, &without_snapshot()).await;
        assert_eq!(deliveries(&ctx, conn).await.len(), 1, "the full scan's");
        let alerted = "UPDATE findings SET alerted_at = now() WHERE connection_id = $1";
        ctx.db
            .execute_raw(opsagent_brain::adapters::db::ledger_storage::stmt(
                alerted,
                vec![conn.into()],
            ))
            .await
            .unwrap();
        // Nothing new: no delivery.
        watch_run(&ctx, conn, 1, &watch(&ctx, without_snapshot())).await;
        assert_eq!(deliveries(&ctx, conn).await.len(), 1);
        // The public snapshot opens: exactly one delivery, a microsecond after its slot.
        let w = watch_run(&ctx, conn, 2, &watch(&ctx, noisy())).await;
        let d = deliveries(&ctx, conn).await;
        assert_eq!(d.len(), 2);
        let slot = w.scheduled_at + chrono::Duration::microseconds(1);
        assert_eq!(d[1].scheduled_at, slot);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn full_and_watch_scan_of_one_slot_get_a_delivery_each() {
    serve(|req, ctx| async move {
        let conn = connection(&req, &ctx).await;
        let full = scan(&ctx, conn, 0, &noisy()).await;
        let f = runs::Entity::find_by_id(full)
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        // Same slot; the full scan's criticals are still unalerted (its delivery has not run).
        let at = f.scheduled_at.with_timezone(&chrono::Utc);
        watch_run_at(&ctx, conn, at, &watch(&ctx, noisy())).await;
        let d = deliveries(&ctx, conn).await;
        assert_eq!(d.len(), 2, "no key collision");
        assert_eq!(d[0].scheduled_at, f.scheduled_at);
        assert_eq!(
            d[1].scheduled_at,
            f.scheduled_at + chrono::Duration::microseconds(1)
        );
    })
    .await;
}
