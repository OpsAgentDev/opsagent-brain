//! The organisation purge over the in-memory tables (`RetentionRepo::purge_org`).
use std::collections::HashMap;

use opsagent_core::retention::PurgeCounts;
use uuid::Uuid;

use super::MemState;

/// Removes the rows `gone` picks; returns how many.
pub(super) fn drain<T>(rows: &mut Vec<T>, gone: impl Fn(&T) -> bool) -> u64 {
    let n = rows.len();
    rows.retain(|r| !gone(r));
    (n - rows.len()) as u64
}

/// `drain` for a map, by key.
fn drain_keys<K, V>(rows: &mut HashMap<K, V>, gone: impl Fn(&K) -> bool) -> u64 {
    let n = rows.len();
    rows.retain(|k, _| !gone(k));
    (n - rows.len()) as u64
}

impl MemState {
    /// Deletes every row of `org`, its orphaned users and the organisation; the counts per
    /// table, named as in Postgres (tables not modelled here are absent).
    pub(super) fn purge(&mut self, org: Uuid) -> PurgeCounts {
        let mut c = self.purge_operational(org);
        let s = self;
        let one = Some(org);
        let users: Vec<Uuid> = s
            .members
            .iter()
            .filter(|m| m.organisation_id == org)
            .map(|m| m.user_id)
            .collect();
        let grants: Vec<Uuid> = s
            .oauth_grants
            .iter()
            .filter(|g| g.organisation_id == org)
            .map(|g| g.id)
            .collect();
        let conns: Vec<Uuid> = s
            .connections
            .iter()
            .filter(|x| x.0.organisation_id == org)
            .map(|x| x.0.id)
            .collect();
        let mut put = |table, n| c.insert(table, n);
        put(
            "recipients",
            drain(&mut s.recipients, |r| r.row.organisation_id == org),
        );
        put(
            "oauth_consent_requests",
            drain(&mut s.oauth_consents, |r| {
                r.organisation_id == one || r.grant_id.is_some_and(|g| grants.contains(&g))
            }),
        );
        put(
            "oauth_access_tokens",
            drain(&mut s.oauth_access, |t| t.organisation_id == org),
        );
        put(
            "oauth_refresh_tokens",
            drain(&mut s.oauth_refresh, |t| t.organisation_id == org),
        );
        put(
            "oauth_grants",
            drain(&mut s.oauth_grants, |g| g.organisation_id == org),
        );
        put(
            "connection_verifications",
            drain(&mut s.verifications, |v| conns.contains(&v.0)),
        );
        put(
            "connections",
            drain(&mut s.connections, |x| x.0.organisation_id == org),
        );
        put(
            "integrations",
            drain(&mut s.integrations, |i| i.organisation_id == org),
        );
        put(
            "invites",
            drain(&mut s.invites, |i| i.invite.organisation_id == org),
        );
        put(
            "email_suppressions",
            drain(&mut s.suppressions, |x| x.organisation_id == one),
        );
        put(
            "members",
            drain(&mut s.members, |m| m.organisation_id == org),
        );
        let members = &s.members;
        let orphans: Vec<Uuid> = users
            .into_iter()
            .filter(|u| !members.iter().any(|m| m.user_id == *u))
            .collect();
        put(
            "magic_links",
            drain(&mut s.magic_links, |l| orphans.contains(&l.user_id)),
        );
        put(
            "passkeys",
            drain(&mut s.passkeys, |p| orphans.contains(&p.user_id)),
        );
        put("users", drain(&mut s.users, |u| orphans.contains(&u.id)));
        put("organisations", drain(&mut s.orgs, |o| o.id == org));
        c
    }

    /// The organisation's audit trail, runs and what hangs off them, findings and resources.
    fn purge_operational(&mut self, org: Uuid) -> PurgeCounts {
        let s = self;
        let one = Some(org);
        let runs: Vec<Uuid> = s
            .runs
            .iter()
            .filter(|r| r.row.key.organisation_id == one)
            .map(|r| r.row.id)
            .collect();
        let mut c = PurgeCounts::new();
        let mut put = |table, n| c.insert(table, n);
        put(
            "audit_events",
            drain(&mut s.audit, |e| e.organisation_id == one),
        );
        put(
            "side_effects",
            drain_keys(&mut s.effects, |k| runs.contains(&k.0)),
        );
        s.effects_done_at.retain(|k, _| !runs.contains(&k.0));
        put("jobs", drain(&mut s.jobs, |j| runs.contains(&j.run_id)));
        put(
            "findings",
            drain(&mut s.findings, |f| f.finding.organisation_id == org),
        );
        put(
            "resources",
            drain(&mut s.resources, |r| r.organisation_id == org),
        );
        put(
            "deliveries",
            drain(&mut s.deliveries, |d| d.organisation_id == org),
        );
        put(
            "schedules",
            drain(&mut s.schedules, |x| x.organisation_id == one),
        );
        put("runs", drain(&mut s.runs, |r| runs.contains(&r.row.id)));
        c
    }
}
