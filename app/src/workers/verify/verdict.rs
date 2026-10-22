//! The verdict of one verify call, by priority (PRD 7.2).
use opsagent_connectors::{aws::policy_diff::grant_names, VerifyOutcome};
use opsagent_core::connection::ConnectionEvent as E;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    /// Role assume with the ExternalId was denied.
    Denied,
    Event(E, Option<String>),
}

fn names(grants: &[String]) -> String {
    grant_names(grants.iter().map(String::as_str)).join(", ")
}

/// Order matters: the confused-deputy guard wins over everything else.
pub(super) fn decide(o: &VerifyOutcome) -> Verdict {
    if !o.assume_without_denied {
        Verdict::Event(
            E::ExternalIdNotEnforced,
            Some("external_id_not_enforced".into()),
        )
    } else if !o.assume_with_ok {
        Verdict::Denied
    } else if !o.account_matches {
        // No dedicated event: an account mismatch is blocked exactly like a superset.
        Verdict::Event(E::VerifySuperset, Some("account_mismatch".into()))
    } else if !o.extra_grants.is_empty() {
        let reason = format!("extra_grants: {}", names(&o.extra_grants));
        Verdict::Event(E::VerifySuperset, Some(reason))
    } else if !o.missing_grants.is_empty() {
        let reason = format!("missing_grants: {}", names(&o.missing_grants));
        Verdict::Event(E::VerifySubset, Some(reason))
    } else {
        Verdict::Event(E::VerifyOk, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok() -> VerifyOutcome {
        VerifyOutcome {
            assume_with_ok: true,
            assume_without_denied: true,
            account_matches: true,
            extra_grants: vec![],
            missing_grants: vec![],
        }
    }

    #[test]
    fn decide_maps_outcomes_in_priority_order() {
        assert_eq!(decide(&ok()), Verdict::Event(E::VerifyOk, None));
        let open = VerifyOutcome {
            assume_without_denied: false,
            assume_with_ok: false,
            ..ok()
        };
        assert_eq!(
            decide(&open),
            Verdict::Event(
                E::ExternalIdNotEnforced,
                Some("external_id_not_enforced".into())
            )
        );
        let denied = VerifyOutcome {
            assume_with_ok: false,
            ..ok()
        };
        assert_eq!(decide(&denied), Verdict::Denied);
        let other = VerifyOutcome {
            account_matches: false,
            extra_grants: vec!["ec2:RunInstances on *".into()],
            ..ok()
        };
        assert_eq!(
            decide(&other),
            Verdict::Event(E::VerifySuperset, Some("account_mismatch".into()))
        );
        let both = VerifyOutcome {
            extra_grants: vec!["ec2:RunInstances on *".into()],
            missing_grants: vec!["ec2:Describe* on *".into()],
            ..ok()
        };
        assert_eq!(
            decide(&both),
            Verdict::Event(
                E::VerifySuperset,
                Some("extra_grants: ec2:RunInstances".into())
            )
        );
        let subset = VerifyOutcome {
            missing_grants: vec!["ec2:Describe* on *".into()],
            ..ok()
        };
        assert_eq!(
            decide(&subset),
            Verdict::Event(
                E::VerifySubset,
                Some("missing_grants: ec2:Describe*".into())
            )
        );
    }
}
