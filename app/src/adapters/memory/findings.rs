use async_trait::async_trait;
use chrono::{DateTime, Utc};
use opsagent_core::{
    finding::{
        dedupe, Finding, FindingDraft, FindingEvent, FindingFilter, FindingsRepo, PostureRow,
        Severity, StatusChange, StoredEvidence,
    },
    repo::{Cursor, PageOf, PageRequest, RepoError, RepoResult},
};
use sea_orm::prelude::Decimal;
use uuid::Uuid;

use super::{page, MemStore};
use crate::{adapters::redact::redact, models::enum_str};

#[derive(Clone)]
pub struct FindingRow {
    pub(super) finding: Finding,
    /// Oldest first.
    pub(super) events: Vec<FindingEvent>,
    /// Oldest first.
    evidence: Vec<StoredEvidence>,
}

impl FindingRow {
    fn event(&mut self, kind: &str, run_id: Option<Uuid>, at: DateTime<Utc>) {
        let s = Some(self.finding.severity);
        self.events.push(FindingEvent {
            finding_id: self.finding.id,
            kind: kind.into(),
            run_id,
            from_severity: s,
            to_severity: s,
            at,
        });
    }

    /// shortcut: open, seen, reopen and expiry only; flapping, escalation and the stability
    /// counters are Pg-only (`adapters::db::findings::seen`), tested by the full-scan worker tests.
    fn seen(&mut self, run_id: Uuid, d: &FindingDraft, now: DateTime<Utc>) {
        let f = &mut self.finding;
        let expired = |u: Option<DateTime<Utc>>| u.is_some_and(|u| u <= now);
        let kind = match f.status.as_str() {
            "open" => Some("seen"),
            "accepted" if expired(f.accepted_until) => Some("reopened"),
            "snoozed" if expired(f.snoozed_until) => Some("reopened"),
            "accepted" | "snoozed" | "flapping" => None,
            _ => Some("reopened"),
        };
        if kind == Some("reopened") {
            f.status = "open".into();
            (f.resolved_at, f.resolved_reason) = (None, None);
        }
        (f.severity, f.title, f.last_seen_run_id) = (d.severity, d.title.clone(), Some(run_id));
        f.updated_at = now;
        (f.summary, f.next_step) = (Some(d.summary.clone()), Some(d.next_step.clone()));
        f.cost_monthly_usd = cost(d);
        if let Some(k) = kind {
            self.event(k, Some(run_id), now);
        }
    }
}

/// As Postgres stores it: `numeric(14, 2)`.
fn cost(d: &FindingDraft) -> Option<Decimal> {
    let mut c = Decimal::try_from(d.cost_monthly_usd?).ok()?;
    c.rescale(2);
    Some(c)
}

fn stored(run_id: Uuid, d: &FindingDraft, now: DateTime<Utc>) -> Vec<StoredEvidence> {
    let evidence = d.evidence.iter().map(|e| {
        let ((source, a), (excerpt, b)) = (redact(&e.source), redact(&e.excerpt));
        let redacted = a || b;
        StoredEvidence {
            source,
            excerpt,
            redacted,
            run_id,
            created_at: now,
        }
    });
    evidence.collect()
}

fn key(f: &FindingRow) -> Cursor {
    (f.finding.created_at.into(), f.finding.id)
}

impl MemStore {
    fn finding_row<T>(&self, org: Uuid, id: Uuid, read: impl Fn(&FindingRow) -> T) -> Option<T> {
        let s = self.state();
        let f = s
            .findings
            .iter()
            .find(|f| f.finding.organisation_id == org && f.finding.id == id);
        f.map(read)
    }
}

#[async_trait]
impl FindingsRepo for MemStore {
    async fn get(&self, organisation_id: Uuid, id: Uuid) -> RepoResult<Option<Finding>> {
        Ok(self.finding_row(organisation_id, id, |f| f.finding.clone()))
    }

    async fn list(
        &self,
        organisation_id: Uuid,
        q: FindingFilter,
        p: PageRequest,
    ) -> RepoResult<PageOf<Finding>> {
        let rows = self
            .state()
            .findings
            .iter()
            .filter(|r| {
                let f = &r.finding;
                f.organisation_id == organisation_id
                    && q.connection_id.is_none_or(|c| f.connection_id == c)
                    && q.status.as_ref().is_none_or(|s| &f.status == s)
                    && q.severity.is_none_or(|s| f.severity == s)
                    && q.check_id.as_ref().is_none_or(|c| &f.key.check_id == c)
                    && q.variant.as_ref().is_none_or(|v| &f.key.variant == v)
                    && q.last_seen_since.is_none_or(|t| f.updated_at >= t)
            })
            .cloned()
            .collect();
        let rows = page(rows, key, p);
        Ok(PageOf {
            items: rows.items.into_iter().map(|r| r.finding).collect(),
            next: rows.next,
        })
    }

    async fn events(
        &self,
        organisation_id: Uuid,
        finding_id: Uuid,
    ) -> RepoResult<Vec<FindingEvent>> {
        let events = self.finding_row(organisation_id, finding_id, |f| f.events.clone());
        Ok(events.unwrap_or_default().into_iter().rev().collect())
    }

    /// shortcut: evidence never expires here; expiry is Pg-only (`expires_at`).
    async fn evidence(
        &self,
        organisation_id: Uuid,
        finding_id: Uuid,
    ) -> RepoResult<Vec<StoredEvidence>> {
        let ev = self.finding_row(organisation_id, finding_id, |f| f.evidence.clone());
        Ok(ev.unwrap_or_default().into_iter().rev().collect())
    }

    async fn change_status(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        c: StatusChange,
    ) -> RepoResult<Finding> {
        let mut s = self.state();
        let row = s
            .findings
            .iter_mut()
            .find(|f| f.finding.organisation_id == organisation_id && f.finding.id == id)
            .ok_or(RepoError::NotFound)?;
        if row.finding.status != c.from_status {
            return Err(RepoError::Conflict("finding_state_changed"));
        }
        let f = &mut row.finding;
        f.status = c.status;
        (f.accepted_reason, f.accepted_until) = (c.accepted_reason, c.accepted_until);
        (f.snoozed_until, f.updated_at) = (c.snoozed_until, c.event.at);
        row.events.push(c.event);
        Ok(row.finding.clone())
    }

    async fn upsert_seen(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
        run_id: Uuid,
        drafts: &[FindingDraft],
        now: DateTime<Utc>,
    ) -> RepoResult<()> {
        let mut s = self.state();
        for d in &dedupe(drafts) {
            let found = s.findings.iter_mut().find(|f| {
                f.finding.organisation_id == organisation_id
                    && f.finding.connection_id == connection_id
                    && f.finding.key == d.key
            });
            let row = match found {
                Some(f) if f.finding.last_seen_run_id == Some(run_id) => continue,
                Some(f) => {
                    f.seen(run_id, d, now);
                    f
                }
                None => {
                    s.findings.push(FindingRow {
                        finding: Finding {
                            id: Uuid::now_v7(),
                            organisation_id,
                            connection_id,
                            key: d.key.clone(),
                            severity: d.severity,
                            status: "open".into(),
                            title: d.title.clone(),
                            summary: Some(d.summary.clone()),
                            next_step: Some(d.next_step.clone()),
                            cost_monthly_usd: cost(d),
                            accepted_reason: None,
                            accepted_until: None,
                            snoozed_until: None,
                            first_seen_run_id: Some(run_id),
                            last_seen_run_id: Some(run_id),
                            resolved_at: None,
                            resolved_reason: None,
                            alerted_at: None,
                            created_at: now,
                            updated_at: now,
                        },
                        events: vec![],
                        evidence: vec![],
                    });
                    let f = s.findings.last_mut().expect("just pushed");
                    f.event("opened", Some(run_id), now);
                    f
                }
            };
            row.evidence.retain(|e| e.run_id != run_id);
            row.evidence.extend(stored(run_id, d, now));
        }
        Ok(())
    }

    async fn resolve_unseen(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
        run_id: Uuid,
        except_check_ids: &[String],
        now: DateTime<Utc>,
    ) -> RepoResult<u64> {
        let mut n = 0;
        let mut s = self.state();
        let gone = s.gone_identities(organisation_id, connection_id);
        for row in s.findings.iter_mut().filter(|r| {
            let f = &r.finding;
            f.organisation_id == organisation_id
                && f.connection_id == connection_id
                && !except_check_ids.contains(&f.key.check_id)
                && matches!(f.status.as_str(), "open" | "flapping")
                && f.last_seen_run_id != Some(run_id)
        }) {
            if row.finding.status != "flapping" {
                row.event("resolved", Some(run_id), now);
            }
            let reason = if gone.contains(&row.finding.key.resource_identity) {
                "resource_gone"
            } else {
                "check_passed"
            };
            let f = &mut row.finding;
            (f.status, f.resolved_at) = ("resolved".into(), Some(now));
            f.resolved_reason = Some(reason.into());
            f.alerted_at = None;
            n += 1;
        }
        Ok(n)
    }

    async fn alert_candidates(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
    ) -> RepoResult<Vec<Finding>> {
        let mut out: Vec<Finding> = self
            .state()
            .findings
            .iter()
            .map(|r| &r.finding)
            .filter(|f| {
                f.organisation_id == organisation_id
                    && f.connection_id == connection_id
                    && f.severity == Severity::Critical
                    && f.status == "open"
                    && f.alerted_at.is_none()
            })
            .cloned()
            .collect();
        out.sort_by_key(|f| (f.created_at, f.id));
        Ok(out)
    }

    async fn mark_alerted(
        &self,
        organisation_id: Uuid,
        ids: &[Uuid],
        at: DateTime<Utc>,
    ) -> RepoResult<()> {
        for r in self.state().findings.iter_mut() {
            let f = &mut r.finding;
            if f.organisation_id == organisation_id && ids.contains(&f.id) {
                f.alerted_at = Some(at);
            }
        }
        Ok(())
    }

    async fn posture_rows(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
    ) -> RepoResult<Vec<PostureRow>> {
        let mut rows: Vec<PostureRow> = vec![];
        for f in self
            .state()
            .findings
            .iter()
            .map(|r| &r.finding)
            .filter(|f| {
                f.organisation_id == organisation_id
                    && f.connection_id == connection_id
                    && f.status == "open"
            })
        {
            match rows
                .iter_mut()
                .find(|r| r.check_id == f.key.check_id && r.severity == f.severity)
            {
                Some(r) => r.open += 1,
                None => rows.push(PostureRow {
                    check_id: f.key.check_id.clone(),
                    severity: f.severity,
                    open: 1,
                }),
            }
        }
        rows.sort_by_key(|r| (r.check_id.clone(), enum_str(r.severity)));
        Ok(rows)
    }
}
