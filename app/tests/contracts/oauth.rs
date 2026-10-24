use chrono::{DateTime, Utc};
use opsagent_brain::actions::uow::Repos;
use opsagent_core::oauth::{
    AccessToken, ClientKind, ConsentRequest, Grant, OAuthClient, RefreshToken,
};
use uuid::Uuid;

use super::{contract_suite, org_id};

const CLIENT: &str = "https://app.example/client.json";

fn at(secs: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(1_800_000_000 + secs, 0).unwrap()
}

async fn client(s: &dyn Repos) {
    let c = OAuthClient {
        client_id: CLIENT.into(),
        kind: ClientKind::MetadataDocument,
        name: "Example".into(),
        redirect_uris: vec!["https://app.example/cb".into()],
        document_fetched_at: Some(at(0)),
        document_cache_until: Some(at(3600)),
        last_used_at: None,
        expires_at: None,
    };
    s.oauth().upsert_client(&c).await.unwrap();
}

fn consent(code_hash: Option<&str>) -> ConsentRequest {
    ConsentRequest {
        id: Uuid::new_v4(),
        client_id: CLIENT.into(),
        redirect_uri: "https://app.example/cb".into(),
        code_challenge: "challenge".into(),
        state: Some("st".into()),
        resource: "https://brain.opsagent.dev/mcp".into(),
        scope: "opsagent.read".into(),
        member_id: None,
        organisation_id: None,
        code_hash: code_hash.map(Into::into),
        code_expires_at: code_hash.map(|_| at(60)),
        code_used_at: None,
        grant_id: None,
        expires_at: at(600),
    }
}

async fn grant(s: &dyn Repos, organisation_id: Uuid, member_id: Uuid) -> Grant {
    let g = Grant {
        id: Uuid::new_v4(),
        client_id: CLIENT.into(),
        member_id,
        organisation_id,
        created_at: at(0),
        last_used_at: None,
        revoked_at: None,
    };
    s.oauth().insert_grant(&g).await.unwrap();
    g
}

contract_suite! {
    async fn consume_code_is_single_use(s) {
        client(s).await;
        let c = consent(None);
        s.oauth().insert_consent(&c).await.unwrap();
        let (m, o) = (Uuid::new_v4(), org_id(s, "acme").await);
        s.oauth().decide_consent(c.id, m, o, "h1", at(60)).await.unwrap();
        let got = s.oauth().consume_code("h1", at(10)).await.unwrap().unwrap();
        assert_eq!((got.id, got.member_id, got.organisation_id), (c.id, Some(m), Some(o)));
        assert_eq!(got.code_used_at, Some(at(10)));
        assert!(s.oauth().consume_code("h1", at(11)).await.unwrap().is_none());
        // Replay detection still finds the request, and records the grant issued from it.
        let g = grant(s, o, m).await;
        s.oauth().set_consent_grant(c.id, g.id).await.unwrap();
        let again = s.oauth().consent_by_code_hash("h1").await.unwrap().unwrap();
        assert_eq!((again.code_used_at, again.grant_id), (Some(at(10)), Some(g.id)));
        assert!(s.oauth().consent_by_code_hash("nope").await.unwrap().is_none());
    }

    async fn expired_code_is_not_consumed(s) {
        client(s).await;
        let c = consent(None);
        s.oauth().insert_consent(&c).await.unwrap();
        let o = org_id(s, "acme").await;
        s.oauth().decide_consent(c.id, Uuid::new_v4(), o, "h1", at(60)).await.unwrap();
        assert!(s.oauth().consume_code("h1", at(60)).await.unwrap().is_none());
        assert!(s.oauth().consume_code("h1", at(61)).await.unwrap().is_none());
        // Not burned by the failed attempts: it was never used.
        let c = s.oauth().consent(c.id).await.unwrap().unwrap();
        assert_eq!(c.code_used_at, None);
        assert!(s.oauth().consume_code("h1", at(59)).await.unwrap().is_some());
    }

    async fn revoke_member_grants_hides_their_access_tokens(s) {
        client(s).await;
        let o = org_id(s, "acme").await;
        let (m, other) = (Uuid::new_v4(), Uuid::new_v4());
        let (mine, theirs) = (grant(s, o, m).await, grant(s, o, other).await);
        for (g, hash) in [(&mine, "a1"), (&theirs, "a2")] {
            let t = AccessToken {
                id: Uuid::new_v4(), grant_id: g.id, organisation_id: o,
                token_hash: hash.into(), expires_at: at(3600),
            };
            s.oauth().insert_access(&t).await.unwrap();
        }
        let (_, g) = s.oauth().access_by_hash("a1").await.unwrap().unwrap();
        assert_eq!(g.revoked_at, None);
        s.oauth().revoke_member_grants(o, m, at(5)).await.unwrap();
        let (t, g) = s.oauth().access_by_hash("a1").await.unwrap().unwrap();
        assert_eq!((t.grant_id, g.id, g.revoked_at), (mine.id, mine.id, Some(at(5))));
        let (_, g) = s.oauth().access_by_hash("a2").await.unwrap().unwrap();
        assert_eq!(g.revoked_at, None);
        // A second revoke keeps the first stamp.
        s.oauth().revoke_grant(o, mine.id, at(9)).await.unwrap();
        let g = s.oauth().grant(o, mine.id).await.unwrap().unwrap();
        assert_eq!(g.revoked_at, Some(at(5)));
        assert!(s.oauth().access_by_hash("zz").await.unwrap().is_none());
    }

    async fn grants_for_org_excludes_revoked_and_other_orgs(s) {
        client(s).await;
        let (a, b) = (org_id(s, "acme").await, org_id(s, "other").await);
        let (keep, gone, elsewhere) = (
            grant(s, a, Uuid::new_v4()).await,
            grant(s, a, Uuid::new_v4()).await,
            grant(s, b, Uuid::new_v4()).await,
        );
        s.oauth().revoke_grant(a, gone.id, at(1)).await.unwrap();
        let ids: Vec<Uuid> = s.oauth().grants_for_org(a).await.unwrap().iter().map(|g| g.id).collect();
        assert_eq!(ids, vec![keep.id]);
        // A grant is invisible through another organisation's scope, and cannot be revoked there.
        assert!(s.oauth().grant(a, elsewhere.id).await.unwrap().is_none());
        s.oauth().revoke_grant(a, elsewhere.id, at(2)).await.unwrap();
        assert_eq!(s.oauth().grants_for_org(b).await.unwrap().len(), 1);
        s.oauth().revoke_org_grants(b, at(3)).await.unwrap();
        assert!(s.oauth().grants_for_org(b).await.unwrap().is_empty());
        assert!(s.oauth().client_has_live_grant(CLIENT).await.unwrap());
        s.oauth().revoke_org_grants(a, at(4)).await.unwrap();
        assert!(!s.oauth().client_has_live_grant(CLIENT).await.unwrap());
    }

    async fn spend_refresh_records_successor(s) {
        client(s).await;
        let o = org_id(s, "acme").await;
        let g = grant(s, o, Uuid::new_v4()).await;
        let mk = |hash: &str| RefreshToken {
            id: Uuid::new_v4(), grant_id: g.id, organisation_id: o,
            token_hash: hash.into(), expires_at: at(86_400), spent_at: None, successor_id: None,
        };
        let (first, second) = (mk("r1"), mk("r2"));
        s.oauth().insert_refresh(&first).await.unwrap();
        s.oauth().insert_refresh(&second).await.unwrap();
        s.oauth().spend_refresh(o, first.id, second.id, at(7)).await.unwrap();
        let got = s.oauth().refresh_by_hash("r1").await.unwrap().unwrap();
        assert_eq!((got.spent_at, got.successor_id), (Some(at(7)), Some(second.id)));
        let live = s.oauth().refresh_by_hash("r2").await.unwrap().unwrap();
        assert_eq!((live.spent_at, live.successor_id), (None, None));
        // Spending twice does not overwrite the first successor.
        assert!(s.oauth().spend_refresh(o, first.id, Uuid::new_v4(), at(8)).await.is_err());
        let got = s.oauth().refresh_by_hash("r1").await.unwrap().unwrap();
        assert_eq!(got.successor_id, Some(second.id));
        assert!(s.oauth().refresh_by_hash("nope").await.unwrap().is_none());
    }

    async fn touch_slides_dynamic_expiry(s) {
        let day = 86_400;
        let c = OAuthClient {
            client_id: "dyn".into(),
            kind: ClientKind::Dynamic,
            name: "D".into(),
            redirect_uris: vec!["https://a.example/cb".into()],
            document_fetched_at: None,
            document_cache_until: None,
            last_used_at: None,
            expires_at: Some(at(90 * day)),
        };
        s.oauth().upsert_client(&c).await.unwrap();
        s.oauth().touch_client("dyn", at(89 * day)).await.unwrap();
        let d = s.oauth().client("dyn").await.unwrap().unwrap();
        assert_eq!(d.expires_at, Some(at(179 * day)));
        // A metadata document's expires_at stays NULL.
        client(s).await;
        s.oauth().touch_client(CLIENT, at(5)).await.unwrap();
        assert_eq!(s.oauth().client(CLIENT).await.unwrap().unwrap().expires_at, None);
    }

    async fn client_upsert_keeps_last_used(s) {
        client(s).await;
        s.oauth().touch_client(CLIENT, at(3)).await.unwrap();
        let mut c = s.oauth().client(CLIENT).await.unwrap().unwrap();
        assert_eq!((c.kind, c.redirect_uris.len(), c.last_used_at), (ClientKind::MetadataDocument, 1, Some(at(3))));
        c.name = "Renamed".into();
        c.redirect_uris.push("http://127.0.0.1/cb".into());
        c.last_used_at = None;
        s.oauth().upsert_client(&c).await.unwrap();
        let c = s.oauth().client(CLIENT).await.unwrap().unwrap();
        assert_eq!((c.name.as_str(), c.redirect_uris.len(), c.last_used_at), ("Renamed", 2, Some(at(3))));
        assert!(s.oauth().client("other").await.unwrap().is_none());
    }
}
