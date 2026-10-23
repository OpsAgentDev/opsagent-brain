use chrono::Utc;
use opsagent_core::repo::RepoError;
use opsagent_deliver::repo::{SealedToken, REVOKED, SLACK};
use serde_json::json;

use super::{contract_suite, org_id};

fn token() -> SealedToken {
    SealedToken {
        ciphertext: vec![1, 2],
        nonce: vec![3; 12],
        kek_version: 1,
    }
}

contract_suite! {
    async fn active_slack_ignores_revoked(s) {
        let o = org_id(s, "acme").await;
        let i = s.integrations();
        i.upsert_slack(o, json!({"team_id": "T1", "team_name": "Acme"}), token()).await.unwrap();
        let got = i.active_slack(o).await.unwrap().unwrap();
        assert_eq!((got.kind.as_str(), got.config["team_name"].as_str()), (SLACK, Some("Acme")));
        assert_eq!((got.ciphertext.as_slice(), got.nonce.len()), (&[1u8, 2][..], 12));
        i.mark_revoked(o, got.id, Utc::now()).await.unwrap();
        assert!(i.active_slack(o).await.unwrap().is_none());
        let all = i.list(o).await.unwrap();
        assert_eq!(all.iter().map(|r| r.status.as_str()).collect::<Vec<_>>(), [REVOKED]);
        // A reinstall makes the same row active again.
        i.upsert_slack(o, json!({"team_id": "T1"}), token()).await.unwrap();
        assert_eq!(i.active_slack(o).await.unwrap().map(|r| r.id), Some(got.id));
        let other = org_id(s, "other").await;
        assert!(i.active_slack(other).await.unwrap().is_none());
        assert!(!i.delete(other, got.id).await.unwrap());
        assert!(i.delete(o, got.id).await.unwrap());
        assert!(i.list(o).await.unwrap().is_empty());
    }

    async fn slack_workspace_held_elsewhere_is_conflict(s) {
        let (a, b) = (org_id(s, "a").await, org_id(s, "b").await);
        let i = s.integrations();
        i.upsert_slack(a, json!({"team_id": "T1"}), token()).await.unwrap();
        let err = i.upsert_slack(b, json!({"team_id": "T1"}), token()).await.unwrap_err();
        assert!(matches!(err, RepoError::Conflict("slack_workspace")), "{err:?}");
        let held = i.active_slack(a).await.unwrap().unwrap();
        i.mark_revoked(a, held.id, Utc::now()).await.unwrap();
        i.upsert_slack(b, json!({"team_id": "T1"}), token()).await.unwrap();
    }
}
