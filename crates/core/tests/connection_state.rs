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
    ];
    for (from, ev, to) in cases {
        assert_eq!(transition(from, ev), Ok(to), "{from:?} + {ev:?}");
    }
}

#[test]
fn invalid_transition_is_err() {
    assert!(transition(S::Pending, E::VerifyOk).is_err());
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
    ] {
        assert!(transition(S::Disconnected, ev).is_err(), "{ev:?}");
    }
}
