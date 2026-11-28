use std::sync::Arc;

use chrono::{Days, NaiveDate};
use opsagent_core::{finding::FindingFilter, repo::PageRequest, resource::CostDay};
use uuid::Uuid;

use crate::{
    actions::uow::UnitOfWork,
    error::{AppError, AppResult},
};

/// Days of spend the page shows, ending on the newest stored day.
const WINDOW_DAYS: u64 = 60;
/// Before every stored row: spend is kept 90 days (retention.md), so this reaches all of it.
const BEFORE_ALL: NaiveDate = NaiveDate::from_ymd_opt(2000, 1, 1).unwrap();
/// Check 01 and the variant of its daily cost findings.
const COST_CHECK: &str = "01";
const COST_VARIANT: &str = "cost_anomaly";
/// Findings read per page; the loop follows the cursor to the end.
const FINDINGS_PER_PAGE: u64 = 200;

/// A day check 01 flagged as a cost spike, whatever its finding's status.
#[derive(Debug, Clone, PartialEq)]
pub struct FlaggedDay {
    pub day: NaiveDate,
    pub finding_id: Uuid,
    pub status: String,
}

/// A connection's stored spend for its newest 60 days, with the days check 01 flagged.
#[derive(Debug, Clone, PartialEq)]
pub struct Costs {
    pub newest_day: Option<NaiveDate>,
    pub days: Vec<CostDay>,
    pub flagged: Vec<FlaggedDay>,
}

/// The connection's stored daily spend; `NotFound` for another organisation's connection.
#[derive(Clone)]
pub struct GetCosts {
    uow: Arc<dyn UnitOfWork>,
}

impl GetCosts {
    pub fn new(uow: Arc<dyn UnitOfWork>) -> Self {
        Self { uow }
    }

    pub async fn run(&self, organisation_id: Uuid, connection_id: Uuid) -> AppResult<Costs> {
        let connections = self.uow.connections();
        let found = connections.get(organisation_id, connection_id).await?;
        found.ok_or(AppError::NotFound)?;
        let stored = self.uow.resources();
        let mut days = stored
            .costs(organisation_id, connection_id, BEFORE_ALL)
            .await?;
        let newest_day = days.iter().map(|d| d.day).max();
        // No data: no window, so every flagged day shows.
        let from = newest_day.map(|n| n - Days::new(WINDOW_DAYS - 1));
        days.retain(|d| from.is_none_or(|f| d.day >= f));
        let flagged = self.flagged(organisation_id, connection_id, from).await?;
        Ok(Costs {
            newest_day,
            days,
            flagged,
        })
    }

    /// Check 01's cost-spike findings of the connection for days on or after `from` (any day
    /// when `None`), by day.
    async fn flagged(
        &self,
        organisation_id: Uuid,
        connection_id: Uuid,
        from: Option<NaiveDate>,
    ) -> AppResult<Vec<FlaggedDay>> {
        let filter = FindingFilter {
            connection_id: Some(connection_id),
            check_id: Some(COST_CHECK.into()),
            variant: Some(COST_VARIANT.into()),
            ..Default::default()
        };
        let findings = self.uow.findings();
        let mut out = vec![];
        let mut after = None;
        loop {
            let page = PageRequest {
                after,
                limit: FINDINGS_PER_PAGE,
            };
            let got = findings.list(organisation_id, filter.clone(), page).await?;
            for f in got.items {
                let day = f.key.resource_identity.strip_prefix("cost:");
                let day = day.and_then(|d| d.parse::<NaiveDate>().ok());
                if let Some(day) = day.filter(|d| from.is_none_or(|f| *d >= f)) {
                    out.push(FlaggedDay {
                        day,
                        finding_id: f.id,
                        status: f.status,
                    });
                }
            }
            match got.next {
                Some(next) => after = Some(next),
                None => break,
            }
        }
        out.sort_by_key(|f| f.day);
        Ok(out)
    }
}
