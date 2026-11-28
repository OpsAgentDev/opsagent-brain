use std::collections::BTreeMap;

use chrono::{DateTime, NaiveDate, Utc};
use opsagent_brain::actions::uow::Repos;
use opsagent_core::{
    org::NewOrganisation,
    repo::PageRequest,
    resource::{CostDay, Provider, Resource, ResourceFilter, ResourceKind},
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
            signup_source: None,
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
    async fn observed_and_gone_follow_the_runs_history(s, seed) {
        let (org, conn) = world(s, seed).await;
        let (i1, b1) = (res("i-1", ResourceKind::Compute, 1), res("b-1", ResourceKind::Storage, 2));
        let r1 = seed.run(org, conn).await;
        s.resources().upsert_chunk(org, conn, r1, &[i1.clone(), b1], now()).await.unwrap();
        let r2 = seed.run(org, conn).await;
        s.resources().upsert_chunk(org, conn, r2, std::slice::from_ref(&i1), now()).await.unwrap();
        let seen = s.resources().observed(org, conn, r2, Provider::Fake, "1").await.unwrap();
        assert_eq!(seen, [i1]);
        let (other, _) = world(s, seed).await;
        assert!(s.resources().observed(other, conn, r2, Provider::Fake, "1").await.unwrap().is_empty());
        assert_eq!(s.resources().mark_unseen_gone(other, conn, r2, now()).await.unwrap(), 0);
        assert_eq!(s.resources().mark_unseen_gone(org, conn, r2, now()).await.unwrap(), 1);
        assert_eq!(s.resources().mark_unseen_gone(org, conn, r2, now()).await.unwrap(), 0);
        let rows = s.resources().list(org, ResourceFilter::default(), all()).await.unwrap().items;
        let gone: Vec<_> = rows.iter().filter(|r| r.gone_at.is_some()).map(|r| r.identity.as_str()).collect();
        assert_eq!(gone, ["b-1"]);
    }

    async fn forget_run_drops_only_that_runs_history_in_the_org(s, seed) {
        let (org, conn) = world(s, seed).await;
        let i1 = res("i-1", ResourceKind::Compute, 1);
        let (keep, drop) = (seed.run(org, conn).await, seed.run(org, conn).await);
        for run in [keep, drop] {
            s.resources().upsert_chunk(org, conn, run, std::slice::from_ref(&i1), now()).await.unwrap();
        }
        let (other, _) = world(s, seed).await;
        assert_eq!(s.resources().forget_run(other, conn, drop).await.unwrap(), 0);
        assert_eq!(s.resources().forget_run(org, conn, drop).await.unwrap(), 1);
        assert!(s.resources().observed(org, conn, drop, Provider::Fake, "1").await.unwrap().is_empty());
        let kept = s.resources().observed(org, conn, keep, Provider::Fake, "1").await.unwrap();
        assert_eq!(kept, [i1]);
    }

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

    async fn list_q_matches_name_or_identity_case_insensitively(s, seed) {
        let (org, conn) = world(s, seed).await;
        let run = seed.run(org, conn).await;
        let chunk = [res("snap-public", ResourceKind::Storage, 1), res("i-1", ResourceKind::Compute, 1)];
        s.resources().upsert_chunk(org, conn, run, &chunk, now()).await.unwrap();
        let q = |q: &str| ResourceFilter { q: Some(q.into()), ..Default::default() };
        let found = |f: ResourceFilter| async move {
            s.resources().list(org, f, all()).await.unwrap().items.into_iter().map(|r| r.identity).collect::<Vec<_>>()
        };
        assert_eq!(found(q("SNAP-PUB")).await, ["snap-public"]);
        assert_eq!(found(q("N-I-1")).await, ["i-1"], "name n-i-1 matches");
        // LIKE wildcards are literals.
        assert!(found(q("%")).await.is_empty());
        assert!(found(q("_")).await.is_empty());
        let exact = |i: &str| ResourceFilter { identity: Some(i.into()), ..Default::default() };
        assert_eq!(found(exact("snap-public")).await, ["snap-public"]);
        assert!(found(exact("snap")).await.is_empty(), "no substring match");
    }

    async fn costs_upsert_by_day_and_service_and_stay_in_their_tenant(s, seed) {
        let (org, conn) = world(s, seed).await;
        let day = |n| NaiveDate::from_ymd_opt(2026, 10, n).unwrap();
        let cost = |n, service: &str, usd: &str| CostDay {
            day: day(n),
            service: service.into(),
            amount_usd: usd.parse().unwrap(),
        };
        let first = [cost(1, "ec2", "1.5"), cost(2, "ec2", "2"), cost(2, "s3", "0.00005")];
        s.resources().replace_costs(org, conn, &first, now()).await.unwrap();
        // A re-run restates the same keys; a revised amount overwrites.
        let again = [cost(2, "ec2", "2.25"), cost(3, "ec2", "3")];
        s.resources().replace_costs(org, conn, &again, now()).await.unwrap();
        s.resources().replace_costs(org, conn, &again, now()).await.unwrap();
        let got = s.resources().costs(org, conn, day(1)).await.unwrap();
        // Four decimals, half away from zero.
        let want = [cost(1, "ec2", "1.5"), cost(2, "ec2", "2.25"), cost(2, "s3", "0.0001"), cost(3, "ec2", "3")];
        assert_eq!(got, want);
        let shown: Vec<_> = got.iter().map(|c| c.amount_usd.to_string()).collect();
        assert_eq!(shown, ["1.5000", "2.2500", "0.0001", "3.0000"]);
        assert_eq!(s.resources().costs(org, conn, day(3)).await.unwrap(), [cost(3, "ec2", "3")]);
        // Another organisation, or another connection, sees none of it.
        let (other, other_conn) = world(s, seed).await;
        assert!(s.resources().costs(other, conn, day(1)).await.unwrap().is_empty());
        assert!(s.resources().costs(org, other_conn, day(1)).await.unwrap().is_empty());
        assert!(s.resources().costs(other, other_conn, day(1)).await.unwrap().is_empty());
        s.resources().replace_costs(org, conn, &[], now()).await.unwrap();
    }

    async fn costs_beyond_one_insert_are_all_stored(s, seed) {
        let (org, conn) = world(s, seed).await;
        let day = NaiveDate::from_ymd_opt(2026, 10, 1).unwrap();
        let rows: Vec<CostDay> = (0..1200)
            .map(|i| CostDay { day, service: format!("svc-{i:04}"), amount_usd: i.into() })
            .collect();
        s.resources().replace_costs(org, conn, &rows, now()).await.unwrap();
        assert_eq!(s.resources().costs(org, conn, day).await.unwrap(), rows);
    }
}
