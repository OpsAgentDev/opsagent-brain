use opsagent_brain::actions::uow::Repos;
use opsagent_core::{
    connection::{Connection, ConnectionPatch, ConnectionStatus as S, NewConnection, SealedCreds},
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
