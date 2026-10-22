#![allow(dead_code)]
use chrono::{DateTime, Duration, TimeZone, Utc};
use opsagent_core::connection::ConnectionStatus;
use opsagent_core::finding::{FindingKey, Severity};
use opsagent_deliver::model::{
    ConnectionSnapshot, EventKind, FindingSnapshot, FindingStatus, SeverityCounts,
};
use uuid::Uuid;

pub const LINK_BASE: &str = "https://app.example.test";

pub fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 22, 8, 0, 0).unwrap()
}

pub fn since() -> DateTime<Utc> {
    now() - Duration::days(1)
}

pub fn conn() -> ConnectionSnapshot {
    ConnectionSnapshot {
        id: Uuid::nil(),
        display_name: "prod".into(),
        status: ConnectionStatus::Connected,
        status_reason: None,
        posture_score: Some(80.0),
        prev_posture_score: Some(85.0),
        counts_by_severity: SeverityCounts {
            critical: 2,
            high: 1,
            ..Default::default()
        },
        first_scan_at: Some(now() - Duration::days(30)),
        last_scan_at: Some(now() - Duration::hours(6)),
        partial: false,
    }
}

pub fn finding(
    check_id: &str,
    severity: Severity,
    status: FindingStatus,
    events: &[EventKind],
    title: &str,
) -> FindingSnapshot {
    FindingSnapshot {
        id: Uuid::now_v7(),
        key: FindingKey {
            connection_id: Uuid::nil(),
            check_id: check_id.into(),
            resource_identity: title.into(),
            variant: String::new(),
        },
        severity,
        status,
        title: title.into(),
        cost_monthly_usd: None,
        first_seen_at: now() - Duration::days(3),
        last_seen_at: now() - Duration::hours(6),
        events_since: events.to_vec(),
    }
}

pub fn opened(severity: Severity, title: &str) -> FindingSnapshot {
    finding(
        "03",
        severity,
        FindingStatus::Open,
        &[EventKind::Opened],
        title,
    )
}
