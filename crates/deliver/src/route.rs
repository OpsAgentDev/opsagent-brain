//! Where a connection's deliveries go (delivery.md Routing).
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recipient {
    pub id: Uuid,
    pub email: String,
    /// Members get no unsubscribe footer; opt-in non-members do.
    pub member: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    pub slack_channel: Option<String>,
    pub recipients: Vec<Recipient>,
}

/// Connection route wins field by field; unset fields inherit the organisation's.
pub fn resolve(conn_route: Option<Route>, org_route: Route) -> Route {
    let Some(c) = conn_route else {
        return org_route;
    };
    Route {
        slack_channel: c.slack_channel.or(org_route.slack_channel),
        recipients: if c.recipients.is_empty() {
            org_route.recipients
        } else {
            c.recipients
        },
    }
}
