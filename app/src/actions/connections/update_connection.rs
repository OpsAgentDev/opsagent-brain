use std::sync::Arc;

use chrono::NaiveTime;
use opsagent_core::{
    connection::{Connection, ConnectionPatch, ConnectionStatus as S},
    org::valid_name,
    repo::Clock,
};
use opsagent_deliver::schedule;
use opsagent_ledger::JobKind;
use uuid::Uuid;

use super::disconnected;
use crate::{
    actions::uow::UnitOfWork,
    error::{AppError, AppResult},
};

/// The PATCH body as sent; `None` leaves a field as it is, `slack_channel_id: ""` clears it.
#[derive(Debug, Default)]
pub struct PatchInput {
    pub display_name: Option<String>,
    pub scan_time_local: Option<String>,
    pub briefing_time_local: Option<String>,
    pub api_rate_ceiling: Option<i32>,
    pub slack_channel_id: Option<String>,
    pub urgent_alerts: Option<bool>,
}

/// `""` clears; otherwise a Slack conversation id.
fn valid_channel(s: &str) -> AppResult<Option<String>> {
    if s.is_empty() {
        return Ok(None);
    }
    let ok = (9..=21).contains(&s.len())
        && matches!(s.as_bytes()[0], b'C' | b'G')
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
    ok.then(|| Some(s.to_owned()))
        .ok_or_else(|| AppError::Invalid("slack_channel_id must be a Slack channel id".into()))
}

fn valid_hhmm(field: &str, v: Option<&str>) -> AppResult<Option<NaiveTime>> {
    let parse = |s: &str| {
        (s.len() == 5)
            .then(|| NaiveTime::parse_from_str(s, "%H:%M").ok())
            .flatten()
            .ok_or_else(|| AppError::Invalid(format!("{field} must be HH:MM")))
    };
    v.map(parse).transpose()
}

impl PatchInput {
    fn validate(self) -> AppResult<ConnectionPatch> {
        if self.api_rate_ceiling.is_some_and(|r| r < 1) {
            return Err(AppError::Invalid(
                "api_rate_ceiling must be at least 1".into(),
            ));
        }
        let name = self.display_name.as_deref().map(valid_name).transpose();
        Ok(ConnectionPatch {
            display_name: name.map_err(|e| AppError::Invalid(e.into()))?,
            scan_time_local: valid_hhmm("scan_time_local", self.scan_time_local.as_deref())?,
            briefing_time_local: valid_hhmm(
                "briefing_time_local",
                self.briefing_time_local.as_deref(),
            )?,
            api_rate_ceiling: self.api_rate_ceiling,
            slack_channel_id: self
                .slack_channel_id
                .as_deref()
                .map(valid_channel)
                .transpose()?,
            urgent_alerts: self.urgent_alerts,
        })
    }
}

/// Applies a patch, for owners. A new scan time rewrites the nightly `full_scan` schedule,
/// effective from the next local day so today's scan neither repeats nor moves (PRD 7.3). A
/// new briefing time rewrites `deliver_briefing`, effective from its next occurrence. One
/// transaction.
pub struct UpdateConnection {
    uow: Arc<dyn UnitOfWork>,
    clock: Arc<dyn Clock>,
}

impl UpdateConnection {
    pub fn new(uow: Arc<dyn UnitOfWork>, clock: Arc<dyn Clock>) -> Self {
        Self { uow, clock }
    }

    /// `NotFound` first, then the patch's validation, then `connection_disconnected`.
    pub async fn run(
        &self,
        organisation_id: Uuid,
        id: Uuid,
        input: PatchInput,
    ) -> AppResult<Connection> {
        let tx = self.uow.begin().await?;
        let c = tx.connections().get(organisation_id, id).await?;
        let c = c.ok_or(AppError::NotFound)?;
        let p = input.validate()?;
        if c.status == S::Disconnected {
            return Err(disconnected());
        }
        let (scan_time, briefing_time) = (p.scan_time_local, p.briefing_time_local);
        let updated = tx.connections().update(organisation_id, id, p).await?;
        let now = self.clock.now();
        let schedules = tx.schedules();
        if let Some(t) = scan_time {
            let from = |tz: &str| schedule::end_of_local_day(tz, now);
            let (job, cron) = (JobKind::FullScan.as_str(), schedule::daily_at(t));
            schedules
                .set_cron(organisation_id, id, job, &cron, &from)
                .await?;
        }
        if let Some(t) = briefing_time {
            // From now: a later time today still briefs today; an already-sent briefing makes
            // the next one "nothing changed" unless something did.
            let (job, cron) = (JobKind::DeliverBriefing.as_str(), schedule::daily_at(t));
            schedules
                .set_cron(organisation_id, id, job, &cron, &|_| Some(now))
                .await?;
        }
        tx.commit().await?;
        Ok(updated)
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Duration, Utc};
    use opsagent_core::repo::FixedClock;
    use opsagent_deliver::repo::SchedulesRepo;

    use super::*;
    use crate::{actions::runs::test_support::connected, adapters::memory::MemStore};

    /// Each schedule of the connection's `(job_type, cron)`, read through `lock_due`.
    async fn crons(store: &MemStore, at: DateTime<Utc>) -> Vec<(String, String)> {
        let mut out = vec![];
        for id in store.due_ids(at).await.unwrap() {
            let (key, cron, _) = store.lock_due(id, at).await.unwrap().unwrap();
            out.push((key.job_type, cron));
        }
        out.sort();
        out
    }

    #[tokio::test]
    async fn update_briefing_time_moves_schedule_in_same_tx() {
        let store = MemStore::default();
        let org = Uuid::new_v4();
        let c = connected(&store, org).await;
        let now: DateTime<Utc> = "2026-10-22T12:00:00Z".parse().unwrap();
        store
            .create_defaults(org, c.id, (None, None), now)
            .await
            .unwrap();
        let far = now + Duration::days(8);
        let before = crons(&store, far).await;
        let update = UpdateConnection::new(Arc::new(store.clone()), Arc::new(FixedClock(now)));
        let input = PatchInput {
            briefing_time_local: Some("07:30".into()),
            ..PatchInput::default()
        };
        let updated = update.run(org, c.id, input).await.unwrap();
        assert_eq!(
            updated.briefing_time_local,
            NaiveTime::from_hms_opt(7, 30, 0)
        );
        let after = crons(&store, far).await;
        let briefing = |v: &[(String, String)]| {
            v.iter()
                .find(|(j, _)| j == "deliver_briefing")
                .map(|(_, c)| c.clone())
        };
        assert_eq!(
            briefing(&after),
            Some(schedule::daily_at(updated.briefing_time_local.unwrap()))
        );
        assert_ne!(briefing(&before), briefing(&after));
        // Only the briefing moved.
        let others = |v: &[(String, String)]| {
            v.iter()
                .filter(|(j, _)| j != "deliver_briefing")
                .cloned()
                .collect::<Vec<_>>()
        };
        assert_eq!(others(&before), others(&after));
        // A refused patch (validation after the read) writes neither the row nor a schedule.
        let bad = PatchInput {
            briefing_time_local: Some("08:00".into()),
            api_rate_ceiling: Some(0),
            ..PatchInput::default()
        };
        let err = update.run(org, c.id, bad).await.unwrap_err();
        assert!(matches!(err, AppError::Invalid(_)), "{err:?}");
        assert_eq!(crons(&store, far).await, after);
    }
}
