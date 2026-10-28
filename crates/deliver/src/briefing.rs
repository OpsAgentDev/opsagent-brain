//! Morning briefing (delivery.md, PRD 7.6): exceptions only, max 10 items, never split.
use chrono::{DateTime, Duration, Utc};
use opsagent_core::connection::ConnectionStatus;
use opsagent_core::finding::Severity;

use crate::model::{
    by_severity, connection_link, Briefing, ConnectionSnapshot, DailyCounts, EventKind,
    FindingSnapshot, FindingStatus, Health, Item,
};

pub const MAX_ITEMS: usize = 10;
const STALE_AFTER: Duration = Duration::hours(48);

/// `None` when there is nothing to say since `since`.
pub fn build_briefing(
    conn: &ConnectionSnapshot,
    findings: &[FindingSnapshot],
    since: DateTime<Utc>,
    now: DateTime<Utc>,
    link_base: &str,
) -> Option<Briefing> {
    let link = connection_link(link_base, conn.id);
    if conn.first_scan_at.is_some_and(|t| t >= since) {
        return Some(Briefing::FirstScan {
            counts: conn.counts_by_severity,
            link,
        });
    }
    let has = |f: &FindingSnapshot, k: EventKind| f.events_since.contains(&k);
    let live =
        |f: &FindingSnapshot| matches!(f.status, FindingStatus::Open | FindingStatus::Flapping);
    let is_new = |f: &FindingSnapshot| {
        live(f)
            && matches!(f.severity, Severity::Critical | Severity::High)
            && (has(f, EventKind::Opened) || has(f, EventKind::Reopened))
    };
    let pick = |keep: &dyn Fn(&FindingSnapshot) -> bool| {
        let mut v: Vec<Item> = findings.iter().filter(|f| keep(f)).map(Item::of).collect();
        by_severity(&mut v);
        v
    };
    let tz: chrono_tz::Tz = conn.timezone.parse().unwrap_or(chrono_tz::UTC);
    let mut new = pick(&is_new);
    for i in &mut new {
        let f = findings.iter().find(|f| f.id == i.id);
        i.alerted = f
            .filter(|f| f.severity == Severity::Critical)
            .and_then(|f| f.alerted_at)
            .map(|t| t.with_timezone(&tz).format("%H:%M").to_string());
    }
    let escalated = pick(&|f| live(f) && !is_new(f) && has(f, EventKind::Escalated));
    let resolved = pick(&|f| {
        f.status == FindingStatus::Resolved
            && f.severity == Severity::Critical
            && has(f, EventKind::Resolved)
    });
    let health = health(conn, now);
    if new.is_empty() && escalated.is_empty() && resolved.is_empty() && health.is_none() {
        return None;
    }
    let counts = DailyCounts {
        new_critical_high: new.len(),
        escalated: escalated.len(),
        resolved_critical: resolved.len(),
        open: conn.counts_by_severity,
    };
    let mut room = MAX_ITEMS;
    let mut cap = |mut v: Vec<Item>| {
        v.truncate(room);
        room -= v.len();
        v
    };
    Some(Briefing::Daily {
        new_critical_high: cap(new),
        escalated: cap(escalated),
        resolved_critical: cap(resolved),
        health,
        counts,
        link,
    })
}

fn health(conn: &ConnectionSnapshot, now: DateTime<Utc>) -> Option<Health> {
    let stale = conn.last_scan_at.is_some_and(|t| now - t > STALE_AFTER);
    let ok = conn.status == ConnectionStatus::Connected && !conn.partial && !stale;
    (!ok).then(|| Health {
        status: conn.status,
        reason: conn.status_reason.clone(),
        partial: conn.partial,
        stale,
    })
}
