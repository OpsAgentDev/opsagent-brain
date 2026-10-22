//! Weekly report (delivery.md Weekly report sections).
use chrono::{DateTime, Duration, Utc};
use opsagent_core::finding::Severity;

use crate::model::{
    by_severity, connection_link, BackupStatus, ConnectionSnapshot, CostAction, EventKind,
    FindingSnapshot, FindingStatus, IamDelta, Item, PostureDelta, SpendSection, SpendSnapshot,
    Weekly, WeeklyExtras,
};

/// "Need a human?" consultancy link, in every weekly report.
pub const NEED_A_HUMAN_URL: &str = "https://harun.dev";
const AWAITING_MAX: usize = 10;

pub fn build_weekly(
    conn: &ConnectionSnapshot,
    findings: &[FindingSnapshot],
    spend: &SpendSnapshot,
    extras: &WeeklyExtras,
    now: DateTime<Utc>,
    link_base: &str,
) -> Weekly {
    // Flapping is live, as in the daily briefing.
    let open =
        |f: &&FindingSnapshot| matches!(f.status, FindingStatus::Open | FindingStatus::Flapping);
    let check = |id: &'static str| move |f: &&FindingSnapshot| f.key.check_id == id;
    let items = |it: &mut dyn Iterator<Item = &FindingSnapshot>| {
        let mut v: Vec<Item> = it.map(Item::of).collect();
        by_severity(&mut v);
        v
    };
    let iam: Vec<_> = findings.iter().filter(check("02")).collect();
    let mut awaiting = items(
        &mut findings
            .iter()
            .filter(open)
            .filter(|f| matches!(f.severity, Severity::Critical | Severity::High)),
    );
    awaiting.truncate(AWAITING_MAX);
    Weekly {
        connection_name: conn.display_name.clone(),
        first_week: conn
            .first_scan_at
            .is_none_or(|t| now - t < Duration::days(7)),
        spend: SpendSection {
            this_week_usd: spend.this_week_usd,
            last_week_usd: spend.last_week_usd,
            delta_usd: spend.this_week_usd - spend.last_week_usd,
            anomalies: spend.anomalies.clone(),
        },
        recommended_cost_action: findings
            .iter()
            .filter(open)
            .filter_map(|f| f.cost_monthly_usd.map(|c| (f, c)))
            .max_by(|a, b| a.1.total_cmp(&b.1))
            .map(|(f, c)| CostAction {
                id: f.id,
                title: f.title.clone(),
                savings_monthly_usd: c,
            }),
        posture: PostureDelta {
            score: conn.posture_score,
            delta: conn
                .posture_score
                .zip(conn.prev_posture_score)
                .map(|(a, b)| a - b),
        },
        iam: IamDelta {
            open: iam.iter().copied().filter(open).count(),
            opened: iam
                .iter()
                .filter(|f| f.events_since.contains(&EventKind::Opened))
                .count(),
            resolved: iam
                .iter()
                .filter(|f| f.events_since.contains(&EventKind::Resolved))
                .count(),
        },
        backups: BackupStatus {
            open_issues: findings.iter().filter(check("04")).filter(open).count(),
            last_restore_test_on: extras.last_restore_test_on,
        },
        certificates: items(&mut findings.iter().filter(check("05")).filter(open)),
        untagged_spend_pct: extras.untagged_spend_pct,
        awaiting_decision: awaiting,
        would_have_done: extras.would_have_done.clone(),
        inventory: conn.counts_by_severity,
        link: connection_link(link_base, conn.id),
        need_a_human_url: NEED_A_HUMAN_URL.into(),
    }
}
