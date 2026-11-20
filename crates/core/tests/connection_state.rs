use opsagent_core::connection::{transition, ConnectionEvent as E, ConnectionStatus as S};

#[test]
fn listed_transitions() {
    let cases = [
        (S::Pending, E::StackReported, S::Verifying),
        (S::Verifying, E::VerifyOk, S::Connected),
        (S::Verifying, E::VerifySubset, S::Degraded),
        (S::Verifying, E::VerifySuperset, S::Blocked),
        (S::Verifying, E::ExternalIdNotEnforced, S::Blocked),
        (S::Connected, E::VerifySubset, S::Degraded),
        (S::Connected, E::AccessDeniedThrice, S::Revoked),
        (S::Connected, E::Disconnect, S::Disconnected),
        (S::Blocked, E::Disconnect, S::Disconnected),
        (S::Pending, E::Disconnect, S::Disconnected),
        (S::Revoked, E::Disconnect, S::Disconnected),
        (S::Degraded, E::VerifyOk, S::Connected),
        (S::Degraded, E::VerifySuperset, S::Blocked),
        (S::Revoked, E::RoleReturned, S::Verifying),
        (S::Blocked, E::VerifyOk, S::Connected),
        (S::Connected, E::ScansFailedThrice, S::Degraded),
        (S::Degraded, E::ScanDone, S::Connected),
    ];
    for (from, ev, to) in cases {
        assert_eq!(transition(from, ev), Ok(to), "{from:?} + {ev:?}");
    }
}

#[test]
fn invalid_transition_is_err() {
    assert!(transition(S::Pending, E::VerifyOk).is_err());
}

/// Failing scans degrade only a connected connection, and a finished scan restores only a
/// degraded one: every other status is left alone.
#[test]
fn scan_events_touch_only_connected_and_degraded() {
    use S::*;
    for from in [Pending, Verifying, Degraded, Revoked, Blocked, Disconnected] {
        assert!(transition(from, E::ScansFailedThrice).is_err(), "{from:?}");
    }
    for from in [
        Pending,
        Verifying,
        Connected,
        Revoked,
        Blocked,
        Disconnected,
    ] {
        assert!(transition(from, E::ScanDone).is_err(), "{from:?}");
    }
}

#[test]
fn disconnected_is_terminal() {
    use E::*;
    for ev in [
        StackReported,
        VerifyOk,
        VerifySubset,
        VerifySuperset,
        ExternalIdNotEnforced,
        AccessDeniedThrice,
        RoleReturned,
        Disconnect,
        ScansFailedThrice,
        ScanDone,
    ] {
        assert!(transition(S::Disconnected, ev).is_err(), "{ev:?}");
    }
}
