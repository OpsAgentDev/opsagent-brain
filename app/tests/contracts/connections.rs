use opsagent_brain::actions::uow::Repos;
use opsagent_core::{
    connection::{
        Connection, ConnectionPatch, ConnectionStatus as S, NewConnection, SealedCreds,
        Verification, Verified,
    },
    org::NewOrganisation,
    repo::RepoError,
};
use uuid::Uuid;

use super::contract_suite;

pub async fn org(s: &dyn Repos) -> Uuid {
    let id = Uuid::new_v4();
    let new = NewOrganisation {
        id,
        slug: format!("org-{id}"),
        name: "Org".into(),
        timezone: "UTC".into(),
        kek_version: 1,
        wrapped_dek: vec![1, 2, 3],
    };
    s.orgs().insert(new).await.unwrap().id
}

pub fn sealed(b: u8) -> SealedCreds {
    SealedCreds {
        ciphertext: vec![b; 8],
        nonce: vec![b; 12],
        kek_version: 1,
    }
}

fn at(secs: i64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(1_800_000_000 + secs, 0).unwrap()
}

fn verification(outcome: &str, secs: i64) -> Verification {
    Verification {
        outcome: outcome.into(),
        at: at(secs),
        assume_with_ok: Some(true),
        assume_without_denied: Some(true),
        policy_matches: Some(outcome == "connected"),
        extra_grants: serde_json::json!([]),
        missing_grants: serde_json::json!(["ec2:Describe* on *"]),
    }
}

fn verified(account: &str) -> Verified {
    Verified {
        account: Some(account.into()),
        ..Default::default()
    }
}

pub async fn connection(s: &dyn Repos, organisation_id: Uuid, name: &str) -> Connection {
    let new = NewConnection {
        organisation_id,
        provider: "aws".into(),
        display_name: name.into(),
        template_version: Some("1".into()),
        credential_kind: "aws_role".into(),
    };
    s.connections().insert(new, sealed(1)).await.unwrap()
}

contract_suite! {
    async fn cas_status_only_from_expected_state(s) {
        let o = org(s).await;
        let c = connection(s, o, "Prod").await;
        assert_eq!((c.status, c.display_name.as_deref()), (S::Pending, Some("Prod")));
        let repo = s.connections();
        assert!(!repo.cas_status(o, c.id, S::Verifying, S::Connected, None).await.unwrap());
        assert_eq!(repo.get(o, c.id).await.unwrap().unwrap().status, S::Pending);
        assert!(repo.cas_status(o, c.id, S::Pending, S::Verifying, None).await.unwrap());
        let gone = Some("customer_disconnected");
        assert!(repo.cas_status(o, c.id, S::Verifying, S::Disconnected, gone).await.unwrap());
        let now = repo.get(o, c.id).await.unwrap().unwrap();
        assert_eq!((now.status, now.status_reason.as_deref()), (S::Disconnected, gone));
        let other = org(s).await;
        assert!(!repo.cas_status(other, c.id, S::Disconnected, S::Pending, None).await.unwrap());
    }

    async fn last_verification_is_none_without_one_or_in_other_org(s) {
        let (o, other) = (org(s).await, org(s).await);
        let c = connection(s, o, "Prod").await;
        let repo = s.connections();
        assert_eq!(repo.last_verification(o, c.id).await.unwrap(), None);
        assert_eq!(repo.last_verification(other, c.id).await.unwrap(), None);
    }

    async fn last_verification_is_the_latest_and_none_in_other_org(s) {
        let (o, other) = (org(s).await, org(s).await);
        let c = connection(s, o, "Prod").await;
        let repo = s.connections();
        let run = Uuid::new_v4();
        repo.record_verification(o, c.id, run, &verification("degraded", 0)).await.unwrap();
        repo.record_verification(o, c.id, run, &verification("connected", 60)).await.unwrap();
        let last = repo.last_verification(o, c.id).await.unwrap();
        assert_eq!(last, Some(verification("connected", 60)));
        assert_eq!(repo.last_verification(other, c.id).await.unwrap(), None);
        let err = repo.record_verification(other, c.id, run, &verification("x", 0)).await;
        assert!(matches!(err, Err(RepoError::NotFound)), "{err:?}");
    }

    async fn verify_state_round_trips_and_clears_the_streak(s) {
        let (o, other) = (org(s).await, org(s).await);
        let c = connection(s, o, "Prod").await;
        let repo = s.connections();
        repo.record_denial(o, c.id, 2, at(0)).await.unwrap();
        let d = repo.get(o, c.id).await.unwrap().unwrap();
        assert_eq!((d.verify_denied_streak, d.verify_denied_first_at), (2, Some(at(0))));
        let v = Verified {
            reason: Some("missing_grants: ec2:Describe*".into()),
            first_connected_at: Some(at(5)),
            ..verified("111111111111")
        };
        repo.record_verified(o, c.id, v).await.unwrap();
        let g = repo.get(o, c.id).await.unwrap().unwrap();
        assert_eq!((g.verify_denied_streak, g.verify_denied_first_at), (0, None));
        assert_eq!(g.external_account_id.as_deref(), Some("111111111111"));
        assert_eq!(g.status_reason.as_deref(), Some("missing_grants: ec2:Describe*"));
        assert_eq!((g.first_connected_at, g.billable_from), (Some(at(5)), Some(at(5))));
        // No account and no reason: the account stays, the reason is cleared.
        repo.record_verified(o, c.id, Verified::default()).await.unwrap();
        let g = repo.get(o, c.id).await.unwrap().unwrap();
        assert_eq!((g.external_account_id.as_deref(), g.status_reason), (Some("111111111111"), None));
        let err = repo.record_denial(other, c.id, 1, at(0)).await;
        assert!(matches!(err, Err(RepoError::NotFound)), "{err:?}");
        let err = repo.record_verified(other, c.id, Verified::default()).await;
        assert!(matches!(err, Err(RepoError::NotFound)), "{err:?}");
    }

    async fn a_claimed_account_is_unique_per_provider(s) {
        let (oa, ob) = (org(s).await, org(s).await);
        let (a, b) = (connection(s, oa, "A").await, connection(s, ob, "B").await);
        let repo = s.connections();
        repo.record_verified(oa, a.id, verified("222222222222")).await.unwrap();
        assert!(repo.cas_status(oa, a.id, S::Pending, S::Connected, None).await.unwrap());
        // An unclaimed row may carry the account; claiming it is refused.
        repo.record_verified(ob, b.id, verified("222222222222")).await.unwrap();
        let err = repo.cas_status(ob, b.id, S::Pending, S::Connected, None).await;
        assert!(matches!(err, Err(RepoError::Conflict("account"))), "{err:?}");
        assert_eq!(repo.get(ob, b.id).await.unwrap().unwrap().status, S::Pending);
        assert!(repo.cas_status(ob, b.id, S::Pending, S::Blocked, None).await.unwrap());
    }

    async fn get_in_other_org_is_none(s) {
        let (o, other) = (org(s).await, org(s).await);
        let c = connection(s, o, "Prod").await;
        let repo = s.connections();
        assert_eq!(repo.get(o, c.id).await.unwrap(), Some(c.clone()));
        assert_eq!(repo.lock(o, c.id).await.unwrap(), Some(c.clone()));
        assert!(repo.get(other, c.id).await.unwrap().is_none());
        assert!(repo.lock(other, c.id).await.unwrap().is_none());
        assert!(repo.list(other).await.unwrap().is_empty());
        let err = repo.update(other, c.id, ConnectionPatch::default()).await.unwrap_err();
        assert!(matches!(err, RepoError::NotFound), "{err:?}");
        let err = repo.load_creds(other, c.id).await.unwrap_err();
        assert!(matches!(err, RepoError::NotFound), "{err:?}");
        let err = repo.save_creds(other, c.id, sealed(2)).await.unwrap_err();
        assert!(matches!(err, RepoError::NotFound), "{err:?}");
        assert_eq!(repo.load_creds(o, c.id).await.unwrap(), sealed(1));
    }

    async fn update_patches_given_fields_and_list_is_oldest_first(s) {
        let o = org(s).await;
        let (a, b) = (connection(s, o, "A").await, connection(s, o, "B").await);
        let repo = s.connections();
        let t = chrono::NaiveTime::from_hms_opt(7, 30, 0);
        let patch = ConnectionPatch {
            briefing_time_local: t,
            slack_channel_id: Some(Some("C0123456789".into())),
            ..Default::default()
        };
        let u = repo.update(o, a.id, patch).await.unwrap();
        assert_eq!((u.display_name.as_deref(), u.briefing_time_local), (Some("A"), t));
        assert_eq!(u.slack_channel_id.as_deref(), Some("C0123456789"));
        let clear = ConnectionPatch { slack_channel_id: Some(None), ..Default::default() };
        assert!(repo.update(o, a.id, clear).await.unwrap().slack_channel_id.is_none());
        let ids: Vec<_> = repo.list(o).await.unwrap().iter().map(|c| c.id).collect();
        assert_eq!(ids, [a.id, b.id]);
    }

    async fn creds_round_trip_unchanged(s) {
        let o = org(s).await;
        let c = connection(s, o, "Prod").await;
        let repo = s.connections();
        assert_eq!(repo.load_creds(o, c.id).await.unwrap(), sealed(1));
        repo.save_creds(o, c.id, sealed(7)).await.unwrap();
        assert_eq!(repo.load_creds(o, c.id).await.unwrap(), sealed(7));
    }
}
