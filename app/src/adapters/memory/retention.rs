use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    audit::{Actor, AuditEntry},
    finding::{Finding, FindingEvent, FindingKey, Severity, StoredEvidence},
    repo::{RepoError, RepoResult},
    retention::{DueOrg, PurgeCounts, RetentionRepo, TtlTable, ORG_PURGED},
    run::{RunKey, RunStatus},
};
use opsagent_ledger::Storage;
use uuid::Uuid;

use super::{findings::FindingRow, MemStore};

/// A row that points at a run, for seeding run-pruning tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunLink {
    FindingEvent,
    Evidence,
    FirstSeen,
    LastSeen,
    /// A done `side_effects` row with this key.
    Effect(&'static str),
    /// Pg only: not modelled here (no-ops).
    ApiCallStats,
    ApiCallsRaw,
    ResourceHistory,
}

/// A bare open finding of `connection_id`.
fn finding(organisation_id: Uuid, connection_id: Uuid) -> Finding {
    let now = Utc::now();
    Finding {
        id: Uuid::now_v7(),
        organisation_id,
        connection_id,
        key: FindingKey {
            connection_id,
            check_id: "01".into(),
            resource_identity: Uuid::now_v7().to_string(),
            variant: String::new(),
        },
        severity: Severity::Low,
        status: "open".into(),
        title: "t".into(),
        summary: None,
        next_step: None,
        cost_monthly_usd: None,
        accepted_reason: None,
        accepted_until: None,
        snoozed_until: None,
        first_seen_run_id: None,
        last_seen_run_id: None,
        resolved_at: None,
        resolved_reason: None,
        alerted_at: None,
        created_at: now,
        updated_at: now,
    }
}

// shortcut: expiring rows are modelled apart from the typed rows (magic links, invites, ...),
// as one expiry instant per row; model them on the typed rows if a test needs both.
impl MemStore {
    /// Adds one `table` row expiring (or observed) at `at`.
    pub fn seed_expiring(&self, table: TtlTable, at: DateTime<Utc>) {
        self.state().expiring.push((table, at));
    }

    /// Makes every later `purge_org` of `org` fail.
    pub fn fail_purge_of(&self, org: Uuid) {
        self.state().fail_purge = Some(org);
    }

    /// Makes every `delete_expired` take `d` first (tests of the run's deadline).
    pub fn slow_ttl(&self, d: std::time::Duration) {
        self.state().ttl_delay = Some(d);
    }

    /// How many `table` rows are left.
    pub fn expiring_left(&self, table: TtlTable) -> u64 {
        self.state()
            .expiring
            .iter()
            .filter(|r| r.0 == table)
            .count() as u64
    }
}

impl MemStore {
    /// A run with `key` in `status`; returns its id.
    pub async fn seed_run(&self, key: RunKey, status: RunStatus) -> Uuid {
        let id = self.create_run(key).await.expect("create run").run.id;
        let mut s = self.state();
        let r = s.runs.iter_mut().find(|r| r.row.id == id).expect("run");
        r.row.status = status;
        id
    }

    /// One row of kind `link` pointing at `run_id`.
    pub fn seed_run_link(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
        run_id: Uuid,
        link: RunLink,
    ) {
        let mut s = self.state();
        if let RunLink::Effect(key) = link {
            s.effects.insert((run_id, key.to_owned()), Some(None));
            return;
        }
        let mut row = FindingRow {
            finding: finding(organisation_id, connection_id),
            events: vec![],
            evidence: vec![],
        };
        match link {
            RunLink::FindingEvent => row.events.push(FindingEvent {
                finding_id: row.finding.id,
                kind: "seen".into(),
                run_id: Some(run_id),
                from_severity: None,
                to_severity: None,
                at: Utc::now(),
            }),
            RunLink::Evidence => row.evidence.push(StoredEvidence {
                source: "s".into(),
                excerpt: "e".into(),
                redacted: false,
                run_id,
                created_at: Utc::now(),
            }),
            RunLink::FirstSeen => row.finding.first_seen_run_id = Some(run_id),
            RunLink::LastSeen => row.finding.last_seen_run_id = Some(run_id),
            _ => return,
        }
        s.findings.push(row);
    }

    /// Rows still pointing at `run_id` (side effects, finding events, evidence, findings).
    pub fn run_links_left(&self, run_id: Uuid) -> u64 {
        let s = self.state();
        let effects = s.effects.keys().filter(|k| k.0 == run_id).count();
        let found = s.findings.iter().map(|f| {
            let events = f.events.iter().filter(|e| e.run_id == Some(run_id)).count();
            let ev = f.evidence.iter().filter(|e| e.run_id == run_id).count();
            let refs = [f.finding.first_seen_run_id, f.finding.last_seen_run_id];
            events + ev + refs.iter().filter(|r| **r == Some(run_id)).count()
        });
        (effects + found.sum::<usize>()) as u64
    }
}

impl super::MemState {
    /// `org` has a queued run, or a running one started after `busy_since`.
    fn busy(&self, org: Uuid, busy_since: DateTime<Utc>) -> bool {
        self.runs.iter().any(|r| {
            let started = r.started_at.unwrap_or(r.row.key.scheduled_at);
            r.row.key.organisation_id == Some(org)
                && (r.row.status == RunStatus::Queued
                    || (r.row.status == RunStatus::Running && started > busy_since))
        })
    }
}

#[async_trait]
impl RetentionRepo for MemStore {
    async fn delete_expired(
        &self,
        table: TtlTable,
        cutoff: DateTime<Utc>,
        batch: u64,
    ) -> RepoResult<u64> {
        let delay = self.state().ttl_delay;
        if let Some(d) = delay {
            tokio::time::sleep(d).await;
        }
        let mut s = self.state();
        let mut left = batch;
        s.expiring.retain(|&(t, at)| {
            let drop = left > 0 && t == table && at < cutoff;
            left -= u64::from(drop);
            !drop
        });
        Ok(batch - left)
    }

    async fn prune_runs(&self, older_than: DateTime<Utc>, batch: u64) -> RepoResult<u64> {
        let mut s = self.state();
        let pinned = |id: Uuid| {
            let effect = s
                .effects
                .keys()
                .any(|(r, k)| *r == id && k.starts_with("alert:baseline"));
            effect
                || s.findings.iter().any(|f| {
                    f.events.iter().any(|e| e.run_id == Some(id))
                        || f.evidence.iter().any(|e| e.run_id == id)
                        || [f.finding.first_seen_run_id, f.finding.last_seen_run_id]
                            .contains(&Some(id))
                })
        };
        let mut picked: Vec<_> = s
            .runs
            .iter()
            .map(|r| (&r.row.key, r.row.status, r.row.id))
            .filter(|(k, st, id)| {
                let skipped = *st == RunStatus::Skipped;
                k.scheduled_at < older_than
                    && !matches!(st, RunStatus::Queued | RunStatus::Running)
                    && (skipped || ["watch_scan", "deliver_alert"].contains(&k.job_type.as_str()))
                    && !pinned(*id)
            })
            .map(|(k, _, id)| (k.scheduled_at, id))
            .collect();
        picked.sort();
        picked.truncate(batch as usize);
        let ids: Vec<Uuid> = picked.into_iter().map(|p| p.1).collect();
        s.effects.retain(|k, _| !ids.contains(&k.0));
        s.effects_done_at.retain(|k, _| !ids.contains(&k.0));
        s.jobs.retain(|j| !ids.contains(&j.run_id));
        s.runs.retain(|r| !ids.contains(&r.row.id));
        Ok(ids.len() as u64)
    }

    async fn due_orgs(
        &self,
        deleted_before: DateTime<Utc>,
        busy_since: DateTime<Utc>,
    ) -> RepoResult<Vec<DueOrg>> {
        let s = self.state();
        let mut due: Vec<_> = s
            .orgs
            .iter()
            .filter_map(|o| o.deleted_at.map(|at| (at, o.id)))
            .filter(|&(at, _)| at < deleted_before)
            .collect();
        due.sort();
        let due = due.into_iter().map(|(_, id)| DueOrg {
            id,
            busy: s.busy(id, busy_since),
        });
        Ok(due.collect())
    }

    async fn purge_org(
        &self,
        org: Uuid,
        deleted_before: DateTime<Utc>,
        busy_since: DateTime<Utc>,
        at: DateTime<Utc>,
    ) -> RepoResult<Option<PurgeCounts>> {
        let mut s = self.state();
        if s.fail_purge == Some(org) {
            return Err(RepoError::Storage("injected purge failure".into()));
        }
        let due = s
            .orgs
            .iter()
            .any(|o| o.id == org && o.deleted_at.is_some_and(|d| d < deleted_before));
        if !due || s.busy(org, busy_since) {
            return Ok(None);
        }
        let counts = s.purge(org);
        s.audit.push(AuditEntry {
            organisation_id: None,
            actor: Actor::System,
            action: ORG_PURGED.into(),
            target: Some(("organisation", org.to_string())),
            outcome: "success".into(),
            meta: serde_json::json!({ "counts": counts }),
        });
        s.purged_at.push((org, at));
        Ok(Some(counts))
    }

    async fn delete_old_purge_records(&self, before: DateTime<Utc>) -> RepoResult<u64> {
        let s = &mut *self.state();
        let old: Vec<String> = s
            .purged_at
            .iter()
            .filter(|p| p.1 < before)
            .map(|p| p.0.to_string())
            .collect();
        s.purged_at.retain(|p| p.1 >= before);
        Ok(super::purge::drain(&mut s.audit, |e| {
            e.action == ORG_PURGED && e.target.as_ref().is_some_and(|t| old.contains(&t.1))
        }))
    }
}
