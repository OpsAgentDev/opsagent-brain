//! Daily spend response bodies.
use chrono::NaiveDate;
use sea_orm::prelude::Decimal;
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::actions::resources::Costs;

/// One service's spend on one day.
#[derive(Serialize, ToSchema)]
pub struct CostDayOut {
    pub day: NaiveDate,
    /// The provider's service name, as Cost Explorer reports it.
    pub service: String,
    /// Unblended cost in USD, four decimals.
    #[schema(value_type = String, example = "12.3400")]
    pub amount_usd: Decimal,
}

/// A day check 01 flagged as a cost spike.
#[derive(Serialize, ToSchema)]
pub struct FlaggedDay {
    pub day: NaiveDate,
    pub finding_id: Uuid,
    /// The finding's status: `open`, `resolved`, `accepted`, `snoozed` or `flapping`.
    pub status: String,
}

#[derive(Serialize, ToSchema)]
pub struct CostSeries {
    /// The newest day stored; null when no spend is stored yet (a new account, Cost Explorer
    /// not enabled, or a failed read).
    pub newest_day: Option<NaiveDate>,
    /// Up to 60 days ending on `newest_day`, by day then service.
    pub days: Vec<CostDayOut>,
    /// Days within that window which check 01 flagged, by day.
    pub flagged: Vec<FlaggedDay>,
}

pub fn series(c: Costs) -> CostSeries {
    CostSeries {
        newest_day: c.newest_day,
        days: c
            .days
            .into_iter()
            .map(|d| CostDayOut {
                day: d.day,
                service: d.service,
                amount_usd: d.amount_usd,
            })
            .collect(),
        flagged: c
            .flagged
            .into_iter()
            .map(|f| FlaggedDay {
                day: f.day,
                finding_id: f.finding_id,
                status: f.status,
            })
            .collect(),
    }
}
