use chrono::{Duration, DurationRound, Utc};
use opsagent_core::{passkey::StoredPasskey, repo::RepoError, user::Email};
use uuid::Uuid;

use super::contract_suite;

fn passkey(user_id: Uuid, cred: &[u8], age_mins: i64) -> StoredPasskey {
    // Postgres keeps microseconds.
    let at = Utc::now()
        .duration_trunc(Duration::microseconds(1))
        .unwrap();
    StoredPasskey {
        id: Uuid::now_v7(),
        user_id,
        credential_id: cred.to_vec(),
        credential: serde_json::json!({"counter": 0}),
        name: "Key".into(),
        created_at: at - Duration::minutes(age_mins),
        last_used_at: None,
    }
}

contract_suite! {
    async fn passkeys_add_list_find_use_remove(s) {
        let user = |e: &str| Email::parse(e).unwrap();
        let ada = s.users().find_or_create_by_email(&user("ada@example.com")).await.unwrap().id;
        let eve = s.users().find_or_create_by_email(&user("eve@example.com")).await.unwrap().id;
        let (newer, older) = (passkey(ada, &[1], 0), passkey(ada, &[2], 5));
        s.passkeys().add(&newer).await.unwrap();
        s.passkeys().add(&older).await.unwrap();
        let dup = s.passkeys().add(&passkey(eve, &[1], 0)).await;
        assert!(matches!(dup, Err(RepoError::Conflict("passkey_exists"))), "{dup:?}");
        assert_eq!(s.passkeys().for_user(ada).await.unwrap(), vec![older.clone(), newer.clone()]);
        assert!(s.passkeys().for_user(eve).await.unwrap().is_empty());
        assert_eq!(s.passkeys().by_credential_id(&[1]).await.unwrap(), Some(newer.clone()));
        assert_eq!(s.passkeys().by_credential_id(&[3]).await.unwrap(), None);

        let at = newer.created_at + Duration::minutes(1);
        let cred = serde_json::json!({"counter": 7});
        s.passkeys().update_after_use(newer.id, &cred, at).await.unwrap();
        let used = s.passkeys().by_credential_id(&[1]).await.unwrap().unwrap();
        assert_eq!((used.credential, used.last_used_at), (cred.clone(), Some(at)));
        let gone = s.passkeys().update_after_use(Uuid::now_v7(), &cred, at).await;
        assert!(matches!(gone, Err(RepoError::NotFound)));

        assert!(!s.passkeys().remove(eve, newer.id).await.unwrap());
        assert!(s.passkeys().remove(ada, newer.id).await.unwrap());
        assert!(!s.passkeys().remove(ada, newer.id).await.unwrap());
        assert_eq!(s.passkeys().for_user(ada).await.unwrap(), vec![older]);
    }
}
