//! `watch_scan`: the 15-minute subset of the full scan (urgent-alerts spec). It opens findings
//! from `sg`, `rds` and `cloudtrail` only, resolves only its own findings whose resource it
//! read as fixed, and never marks gone or waits on a full scan.
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

use super::full_scan::{cost_rows, fixture, noisy, scan, without_snapshot};
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
        // Both services were read in full, so the two exposure findings resolve as the full
        // scan would resolve them; every other finding is the full scan's.
        for f in all_findings(&ctx, conn).await {
            let id = f.resource_identity.as_str();
            let fixed = f.check_id == "03" && (id == "sg-ssh" || id == "snap-public");
            let want = if fixed { "resolved" } else { "open" };
            assert_eq!(f.status, want, "{id} {}", f.variant);
        }
    })
    .await;
}

/// Kill-and-resume between finalize's commit and its checkpoint: that transaction forgot the
/// run's resource history, so the redelivered finalize must not read "no resources" as
/// "everything is fixed".
#[tokio::test]
#[serial]
async fn watch_finalize_delivered_again_after_its_commit_resolves_nothing() {
    serve(|req, ctx| async move {
        let conn = connection(&req, &ctx).await;
        scan(&ctx, conn, 0, &without_snapshot()).await;
        let ws = watch(&ctx, noisy());
        let first = watch_run(&ctx, conn, 0, &ws).await;
        assert_eq!(outcome(&first), ("done", None));
        let state = || async {
            let mut all: Vec<_> = all_findings(&ctx, conn)
                .await
                .into_iter()
                .map(|f| (f.id, f.status, f.last_seen_run_id))
                .collect();
            all.sort();
            (all, deliveries(&ctx, conn).await.len())
        };
        let before = state().await;
        // The worker died after the commit: the run is still running, finalize not checkpointed.
        let undo = "UPDATE runs SET status = 'running', checkpoint = jsonb_set(checkpoint, \
             '{chunks_done}', (checkpoint->'chunks_done') - 'finalize') WHERE id = $1";
        let st = opsagent_brain::adapters::db::ledger_storage::stmt(undo, vec![first.id.into()]);
        ctx.db.execute_raw(st).await.unwrap();
        ws.run(first.id, RunChunkedOptions::default())
            .await
            .unwrap();
        let again = runs::Entity::find_by_id(first.id)
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(outcome(&again), ("done", None));
        assert_eq!(again.checkpoint["stats"], first.checkpoint["stats"]);
        assert_eq!(state().await, before);
        assert_eq!(finding(&ctx, conn, "sg-ssh").await.unwrap().status, "open");
    })
    .await;
}

/// Runs the connection's `deliver_alert` runs (a finished one is a no-op).
async fn deliver(ctx: &TestApp, conn: Uuid) {
    for d in deliveries(ctx, conn).await {
        perform(ctx, opsagent_ledger::JobKind::DeliverAlert, d.id)
            .await
            .unwrap();
    }
}

#[tokio::test]
#[serial]
async fn a_critical_fixed_and_reopened_the_same_day_alerts_twice() {
    serve(|req, ctx| async move {
        let conn = connection(&req, &ctx).await;
        let mail = prepare(&ctx);
        // The first full scan is the baseline: its criticals get one summary, not an alert each.
        scan(&ctx, conn, 0, &without_snapshot()).await;
        deliver(&ctx, conn).await;
        let mut sent = mail.sent().len();
        // The snapshot goes public, is made private, and goes public again, 15 minutes apart.
        for (n, public) in [(1, true), (2, false), (3, true)] {
            let k = if public { noisy() } else { without_snapshot() };
            let r = watch_run(&ctx, conn, n, &watch(&ctx, k)).await;
            assert_eq!(outcome(&r), ("done", None));
            let snap = finding(&ctx, conn, "snap-public").await.unwrap();
            let want = if public { "open" } else { "resolved" };
            assert_eq!(snap.status, want, "watch {n}");
            assert!(snap.alerted_at.is_none(), "watch {n}");
            deliver(&ctx, conn).await;
            let snap = finding(&ctx, conn, "snap-public").await.unwrap();
            assert_eq!(snap.alerted_at.is_some(), public, "watch {n}");
            let now = mail.sent().len();
            assert_eq!(now > sent, public, "watch {n}: {sent} then {now} mails");
            sent = now;
        }
    })
    .await;
}

#[tokio::test]
#[serial]
async fn watch_scan_resolves_nothing_in_a_region_whose_read_failed() {
    serve(|req, ctx| async move {
        let conn = connection(&req, &ctx).await;
        scan(&ctx, conn, 0, &noisy()).await;
        // The SSH group is closed and the snapshot made private.
        let fixed = || {
            fixture(|v| {
                let all = v["resources"].as_array_mut().unwrap();
                all.retain(|r| r["identity"] != "snap-public");
                for r in all.iter_mut().filter(|r| r["identity"] == "sg-ssh") {
                    r["attributes"]["open_world_ports"] = serde_json::json!([]);
                }
            })
        };
        let status = |identity: &'static str| {
            let ctx = ctx.clone();
            async move {
                let all = all_findings(&ctx, conn).await;
                let f = all
                    .into_iter()
                    .find(|f| f.check_id == "03" && f.resource_identity == identity);
                f.unwrap().status
            }
        };
        // The `sg` read of the group's region fails: the group was not read, so its finding
        // stays; `rds` was read there, so the snapshot's resolves.
        let k = Failing {
            inner: fixed(),
            service: "sg",
            region: Some("local"),
        };
        let r = watch_run(&ctx, conn, 0, &watch(&ctx, k)).await;
        assert_eq!(r.status, "partial");
        assert_eq!(status("sg-ssh").await, "open");
        assert_eq!(status("snap-public").await, "resolved");
        // Read in full, the group's finding resolves too.
        let r = watch_run(&ctx, conn, 1, &watch(&ctx, fixed())).await;
        assert_eq!(outcome(&r), ("done", None));
        assert_eq!(status("sg-ssh").await, "resolved");
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
async fn watch_scan_stores_no_spend() {
    serve(|req, ctx| async move {
        let conn = connection(&req, &ctx).await;
        scan(&ctx, conn, 0, &noisy()).await;
        let before = cost_rows(&ctx, conn).await;
        assert_eq!(before.len(), 60);
        let revised = fixture(|v| v["cost_daily"][59]["amount_usd"] = serde_json::json!(999.0));
        watch_run(&ctx, conn, 0, &watch(&ctx, revised)).await;
        assert_eq!(cost_rows(&ctx, conn).await, before);
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

/// `noisy` whose scoped inventory call for `service` fails, in `region` only when one is set.
#[derive(Clone)]
struct Failing {
    inner: FakeConnector,
    service: &'static str,
    region: Option<&'static str>,
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
        if s.services == [self.service] && self.region.is_none_or(|r| s.regions == [r]) {
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

        // SSH is open to the world and the rds chunk fails: check 03 still runs on what was
        // read (it only opens findings).
        let k = Failing {
            inner: fixture(healthy),
            service: "rds",
            region: None,
        };
        let r = watch_run(&ctx, conn, 0, &watch(&ctx, k)).await;
        assert_eq!(r.status, "partial");
        assert_eq!(
            r.checkpoint["stats"]["skipped_checks"],
            serde_json::json!([])
        );
        assert!(finding(&ctx, conn, "sg-ssh").await.is_some());

        // The trail is off, but its chunk fails: no trail-off finding.
        let k = Failing {
            inner: noisy(),
            service: "cloudtrail",
            region: None,
        };
        let r = watch_run(&ctx, conn, 1, &watch(&ctx, k)).await;
        assert_eq!(r.status, "partial");
        assert_eq!(
            r.checkpoint["stats"]["skipped_checks"],
            serde_json::json!(["06"])
        );
        assert!(!trail_off(ctx.clone()).await);
        assert!(finding(&ctx, conn, "sg-ssh").await.is_some());

        // With every chunk read, the next watch opens it.
        watch_run(&ctx, conn, 2, &watch(&ctx, noisy())).await;
        assert!(trail_off(ctx.clone()).await);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn watch_scan_opens_an_open_admin_port_although_another_region_failed() {
    serve(|req, ctx| async move {
        let conn = connection(&req, &ctx).await;
        scan(&ctx, conn, 0, &noisy()).await;
        // A group in a second region opens Elasticsearch to the world; the `sg` read of the
        // first region fails.
        let k = Failing {
            inner: fixture(|v| {
                let groups = v["resources"].as_array_mut().unwrap();
                let mut sg = groups
                    .iter()
                    .find(|r| r["identity"] == "sg-ssh")
                    .unwrap()
                    .clone();
                sg["identity"] = "sg-search".into();
                sg["region"] = "local-2".into();
                sg["attributes"]["open_world_ports"] = serde_json::json!([9200]);
                groups.push(sg);
            }),
            service: "sg",
            region: Some("local"),
        };
        let r = watch_run(&ctx, conn, 0, &watch(&ctx, k)).await;
        assert_eq!(r.status, "partial");
        let f = finding(&ctx, conn, "sg-search").await.unwrap();
        assert_eq!(
            (f.status.as_str(), f.variant.as_str()),
            ("open", "sg_open_admin_port")
        );
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

/// Retention (retention.md): a watch run over findings that are already open writes no
/// evidence, events or finding refs, so once 14 days old it is pruned.
#[tokio::test]
#[serial]
async fn watch_run_over_open_findings_pins_nothing_and_is_pruned() {
    use opsagent_brain::adapters::db::Pg;
    use opsagent_core::retention::RetentionRepo;
    serve(|req, ctx| async move {
        let conn = connection(&req, &ctx).await;
        scan(&ctx, conn, 0, &noisy()).await;
        let r = watch_run(&ctx, conn, 0, &watch(&ctx, noisy())).await;
        assert_eq!(outcome(&r), ("done", None));
        let count = |sql: &'static str| {
            let db = ctx.db.clone();
            async move {
                let st = sea_orm::Statement::from_sql_and_values(
                    sea_orm::DbBackend::Postgres,
                    sql,
                    vec![r.id.into()],
                );
                let row = db.query_one_raw(st).await.unwrap().unwrap();
                row.try_get::<i64>("", "n").unwrap()
            }
        };
        let pins = "SELECT (SELECT count(*) FROM evidence WHERE run_id = $1) \
             + (SELECT count(*) FROM finding_events WHERE run_id = $1) \
             + (SELECT count(*) FROM findings \
                WHERE first_seen_run_id = $1 OR last_seen_run_id = $1) AS n";
        assert_eq!(count(pins).await, 0);
        let age = "UPDATE runs SET scheduled_at = now() - interval '20 days' WHERE id = $1";
        let st = sea_orm::Statement::from_sql_and_values(
            sea_orm::DbBackend::Postgres,
            age,
            vec![r.id.into()],
        );
        ctx.db.execute_raw(st).await.unwrap();
        let cutoff = chrono::Utc::now() - chrono::Duration::days(14);
        assert_eq!(
            Pg::new(ctx.db.clone())
                .prune_runs(cutoff, 100)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            count("SELECT count(*) AS n FROM runs WHERE id = $1").await,
            0
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn a_watch_scan_behind_by_an_interval_is_skipped_stale() {
    serve(|req, ctx| async move {
        let conn = connection(&req, &ctx).await;
        scan(&ctx, conn, 0, &noisy()).await;
        let late = chrono::Utc::now() - chrono::Duration::minutes(20);
        let r = watch_run_at(&ctx, conn, late, &watch(&ctx, noisy())).await;
        assert_eq!(outcome(&r), ("skipped", Some("stale")));
    })
    .await;
}
