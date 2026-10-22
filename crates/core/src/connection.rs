use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStatus {
    Pending,
    Verifying,
    Connected,
    Degraded,
    Revoked,
    Blocked,
    /// Terminal: customer disconnected. A new connect flow creates a new row.
    Disconnected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionEvent {
    StackReported,
    VerifyOk,
    VerifySubset,
    VerifySuperset,
    ExternalIdNotEnforced,
    AccessDeniedThrice,
    RoleReturned,
    Disconnect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid connection transition: {from:?} on {event:?}")]
pub struct InvalidTransition {
    pub from: ConnectionStatus,
    pub event: ConnectionEvent,
}

/// PRD 7.2. Anything not listed is an error; throttling/5xx never reach here.
pub fn transition(
    from: ConnectionStatus,
    event: ConnectionEvent,
) -> Result<ConnectionStatus, InvalidTransition> {
    use ConnectionEvent as E;
    use ConnectionStatus as S;
    let verifiable = matches!(from, S::Verifying | S::Connected | S::Degraded | S::Blocked);
    let live = matches!(from, S::Connected | S::Degraded);
    let open = from != S::Disconnected;
    match (from, event) {
        (S::Pending, E::StackReported) => Ok(S::Verifying),
        (_, E::VerifyOk) if verifiable => Ok(S::Connected),
        (_, E::VerifySubset) if verifiable => Ok(S::Degraded),
        (_, E::VerifySuperset | E::ExternalIdNotEnforced) if verifiable => Ok(S::Blocked),
        (_, E::AccessDeniedThrice) if live => Ok(S::Revoked),
        (_, E::Disconnect) if open => Ok(S::Disconnected),
        // Full re-verification (policy diff, ExternalId guard) before scanning resumes.
        (S::Revoked, E::RoleReturned) => Ok(S::Verifying),
        _ => Err(InvalidTransition { from, event }),
    }
}
