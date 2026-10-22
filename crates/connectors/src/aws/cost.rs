use super::client::provider_err;
use crate::{ConnectorError, CostRow, Result};
use aws_sdk_costexplorer::types::{
    DateInterval, Granularity, GroupDefinition, GroupDefinitionType,
};
use chrono::{Days, NaiveDate};

pub(crate) const COST_ACTIONS: &[&str] = &["ce:GetCostAndUsage"];

/// One `GetCostAndUsage` request (pages followed): DAILY, grouped by SERVICE, UnblendedCost,
/// for the `days` days ending yesterday (`End` is exclusive).
pub async fn cost_daily(
    ce: &aws_sdk_costexplorer::Client,
    days: u32,
    today: NaiveDate,
) -> Result<Vec<CostRow>> {
    let start = today - Days::new(days.into());
    let period = DateInterval::builder()
        .start(start.to_string())
        .end(today.to_string())
        .build()
        .map_err(provider_err)?;
    let mut rows = vec![];
    let mut token = None;
    loop {
        let out = ce
            .get_cost_and_usage()
            .time_period(period.clone())
            .granularity(Granularity::Daily)
            .metrics("UnblendedCost")
            .group_by(
                GroupDefinition::builder()
                    .r#type(GroupDefinitionType::Dimension)
                    .key("SERVICE")
                    .build(),
            )
            .set_next_page_token(token)
            .send()
            .await
            .map_err(provider_err)?;
        for r in out.results_by_time() {
            let day = r.time_period().map(|p| p.start()).unwrap_or_default();
            let date = NaiveDate::parse_from_str(day, "%Y-%m-%d")
                .map_err(|e| ConnectorError::Provider(format!("cost date {day}: {e}")))?;
            for g in r.groups() {
                let amount = g
                    .metrics()
                    .and_then(|m| m.get("UnblendedCost"))
                    .and_then(|m| m.amount())
                    .unwrap_or("0");
                rows.push(CostRow {
                    date,
                    service: g.keys().first().cloned().unwrap_or_default(),
                    amount_usd: amount.parse().map_err(|e| {
                        ConnectorError::Provider(format!("cost amount {amount}: {e}"))
                    })?,
                });
            }
        }
        token = out.next_page_token;
        if token.is_none() {
            return Ok(rows);
        }
    }
}
