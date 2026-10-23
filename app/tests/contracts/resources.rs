use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use opsagent_brain::actions::uow::Repos;
use opsagent_core::{
    org::NewOrganisation,
    repo::PageRequest,
    resource::{Provider, Resource, ResourceFilter, ResourceKind},
};
use serde_json::json;
use uuid::Uuid;

use super::{contract_suite, Seed};

async fn world(s: &dyn Repos, seed: &dyn Seed) -> (Uuid, Uuid) {
    let id = Uuid::new_v4();
    s.orgs()
        .insert(NewOrganisation {
            id,
            slug: format!("org-{}", id.simple()),
            name: "Org".into(),
            timezone: "UTC".into(),
            kek_version: 1,
            wrapped_dek: vec![1],
        })
        .await
        .unwrap();
    (id, seed.connection(id).await)
}

fn res(identity: &str, kind: ResourceKind, size: i64) -> Resource {
    Resource {
        provider: Provider::Fake,
        account: "1".into(),
        region: "eu-west-1".into(),
        kind,
        identity: identity.into(),
        name: format!("n-{identity}"),
        tags: BTreeMap::from([("env".into(), "prod".into())]),
        attributes: json!({ "size": size }),
        observed_at: now(),
    }
}

fn now() -> DateTime<Utc> {
    "2026-10-22T12:00:00Z".parse().unwrap()
}

fn all() -> PageRequest {
    PageRequest {
        after: None,
        limit: 50,
    }
}

contract_suite! {
    async fn upsert_chunk_unchanged_returns_false(s, seed) {
        let (org, conn) = world(s, seed).await;
        let chunk = [res("i-1", ResourceKind::Compute, 1), res("b-1", ResourceKind::Storage, 2)];
        let r1 = seed.run(org, conn).await;
        assert!(s.resources().upsert_chunk(org, conn, r1, &chunk, now()).await.unwrap());
        let r2 = seed.run(org, conn).await;
        assert!(!s.resources().upsert_chunk(org, conn, r2, &chunk, now()).await.unwrap());
        // Re-running a chunk is safe.
        assert!(!s.resources().upsert_chunk(org, conn, r2, &chunk, now()).await.unwrap());
        let rows = s.resources().list(org, ResourceFilter::default(), all()).await.unwrap().items;
        assert_eq!(rows.len(), 2);
        let compute = ResourceFilter { kind: Some(ResourceKind::Compute), ..Default::default() };
        let rows = s.resources().list(org, compute, all()).await.unwrap().items;
        assert_eq!((rows[0].identity.as_str(), rows[0].kind), ("i-1", ResourceKind::Compute));
        assert_eq!((rows[0].name.as_deref(), rows[0].region.as_deref()), (Some("n-i-1"), Some("eu-west-1")));
        assert_eq!(rows[0].tags.get("env").map(String::as_str), Some("prod"));
        let (other, _) = world(s, seed).await;
        assert!(s.resources().list(other, ResourceFilter::default(), all()).await.unwrap().items.is_empty());
        let elsewhere = ResourceFilter { connection_id: Some(Uuid::new_v4()), ..Default::default() };
        assert!(s.resources().list(org, elsewhere, all()).await.unwrap().items.is_empty());
    }

    async fn upsert_chunk_attribute_change_writes_history(s, seed) {
        let (org, conn) = world(s, seed).await;
        let r1 = seed.run(org, conn).await;
        s.resources().upsert_chunk(org, conn, r1, &[res("i-1", ResourceKind::Compute, 1)], now()).await.unwrap();
        let r2 = seed.run(org, conn).await;
        let changed = [res("i-1", ResourceKind::Compute, 2)];
        assert!(s.resources().upsert_chunk(org, conn, r2, &changed, now()).await.unwrap());
        let r3 = seed.run(org, conn).await;
        assert!(!s.resources().upsert_chunk(org, conn, r3, &changed, now()).await.unwrap());
        let rows = s.resources().list(org, ResourceFilter::default(), all()).await.unwrap().items;
        assert_eq!(rows.len(), 1, "one row per identity; history keeps the versions");
    }
}
