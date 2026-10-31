//! Cached finding explanations (Plan 5 Task 4): `FakeModels` behind the real app and Postgres.
use std::sync::Arc;

use axum_test::TestServer;
use chrono::{Duration, Utc};
use opsagent_brain::{
    adapters::{
        db::{ledger_storage::PgStorage, Pg},
        model::fake::{FakeModels, FakeStep},
    },
    models::_entities::{evidence, findings, organisations},
};
use opsagent_core::{
    ai::{evidence_hash, AiRepo},
    finding::{Evidence, FindingDraft, FindingKey, FindingsRepo, Severity},
    model::Usage,
    run::RunKey,
};
use opsagent_ledger::Storage;
use sea_orm::{entity::prelude::*, ActiveValue::Set, IntoActiveModel};
use serde_json::{json, Value};
use serial_test::serial;
use uuid::Uuid;

use super::support::*;

const CHECK: &str = "s3_public";
const KEY: &str = "sk-ant-opsagent-test";

fn step(text: &str) -> FakeStep {
    FakeStep::Text(text.into(), Usage::default())
}

struct World {
    req: TestServer,
    ctx: TestApp,
    fake: Arc<FakeModels>,
    csrf: String,
    org: String,
    org_id: Uuid,
    conn: Uuid,
}

impl World {
    /// A connected org with AI on and the fake serving `steps`.
    async fn new(req: TestServer, ctx: TestApp, steps: Vec<FakeStep>) -> Self {
        let (csrf, org, conn) = connected(&req, &ctx, "owner@example.com", "noisy").await;
        let fake = Arc::new(FakeModels::scripted(steps));
        ctx.state.set_models(fake.clone());
        let org_id = organisations::Entity::find()
            .filter(organisations::Column::Slug.eq(org.as_str()))
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap()
            .id;
        let w = Self {
            req,
            ctx,
            fake,
            csrf,
            org,
            org_id,
            conn,
        };
        let on = w.on(true).await;
        assert_eq!(on, 200);
        w
    }

    async fn on(&self, on: bool) -> u16 {
        let res = self
            .req
            .patch(&format!("/v1/orgs/{}/ai", self.org))
            .add_header("X-CSRF-Token", &self.csrf)
            .json(&json!({ "enabled": on }))
            .await;
        res.status_code().as_u16()
    }

    /// Records a sighting of `identity` in a new run, with `excerpts` as evidence.
    async fn seen(&self, identity: &str, excerpts: &[&str]) -> Uuid {
        let draft = FindingDraft {
            key: FindingKey {
                connection_id: self.conn,
                check_id: CHECK.into(),
                resource_identity: identity.into(),
                variant: String::new(),
            },
            severity: Severity::High,
            title: format!("Bucket {identity} is public"),
            summary: "s".into(),
            next_step: "Block public access".into(),
            cost_monthly_usd: None,
            evidence: excerpts
                .iter()
                .map(|e| Evidence {
                    source: "s3".into(),
                    excerpt: (*e).into(),
                })
                .collect(),
        };
        let repo = Pg::new(&self.ctx.db);
        let run = PgStorage::new(self.ctx.db.clone())
            .create_run(RunKey {
                organisation_id: Some(self.org_id),
                connection_id: Some(self.conn),
                job_type: "full_scan".into(),
                scheduled_at: Utc::now(),
            })
            .await
            .unwrap()
            .run
            .id;
        repo.upsert_seen(self.org_id, self.conn, run, &[draft], Utc::now())
            .await
            .unwrap();
        self.finding(identity).await.id
    }

    async fn finding(&self, identity: &str) -> findings::Model {
        findings::Entity::find()
            .filter(findings::Column::ResourceIdentity.eq(identity))
            .one(&self.ctx.db)
            .await
            .unwrap()
            .unwrap()
    }

    fn url(&self, id: Uuid) -> String {
        format!("/v1/orgs/{}/findings/{id}/explanation", self.org)
    }

    async fn post(&self, id: Uuid) -> axum_test::TestResponse {
        let t = &self.csrf;
        let res = self.req.post(&self.url(id)).add_header("X-CSRF-Token", t);
        res.await
    }

    async fn expire_evidence(&self, id: Uuid) {
        for e in evidence::Entity::find()
            .filter(evidence::Column::FindingId.eq(id))
            .all(&self.ctx.db)
            .await
            .unwrap()
        {
            let mut a = e.into_active_model();
            a.expires_at = Set((Utc::now() - Duration::days(1)).fixed_offset());
            a.update(&self.ctx.db).await.unwrap();
        }
    }
}

#[tokio::test]
#[serial]
async fn explain_cache_hit_across_two_resources() {
    serve_with(
        |c| c.opsagent = Some(opsagent_brain::config::OpsAgentConnection::anthropic(KEY)),
        |req, ctx| async move {
            let w = World::new(req, ctx, vec![step("What it means\nOne.")]).await;
            let a = w.seen(
                "arn:aws:s3:::alpha-bucket",
                &["alpha-bucket allows public ACL"],
            );
            let b = w.seen(
                "arn:aws:s3:::beta-bucket",
                &["beta-bucket allows public ACL"],
            );
            let (a, b) = (a.await, b.await);
            let ra: Value = w.post(a).await.json();
            let rb: Value = w.post(b).await.json();
            assert_eq!(ra["text"], "What it means\nOne.");
            assert_eq!(ra["text"], rb["text"]);
            assert_eq!(ra["label"], "Generated by AI: may be wrong");
            assert_eq!(ra["provider"], "anthropic");
            assert_eq!(w.fake.requests().len(), 1);
        },
    )
    .await;
}

#[tokio::test]
#[serial]
async fn explain_misses_after_evidence_changes() {
    serve_with(
        |c| c.opsagent = Some(opsagent_brain::config::OpsAgentConnection::anthropic(KEY)),
        |req, ctx| async move {
            let w = World::new(req, ctx, vec![step("first"), step("second")]).await;
            let id = w.seen("arn:aws:s3:::alpha-bucket", &["public ACL"]).await;
            assert_eq!(w.post(id).await.json::<Value>()["text"], "first");
            w.seen("arn:aws:s3:::alpha-bucket", &["public policy"])
                .await;
            assert_eq!(w.post(id).await.json::<Value>()["text"], "second");
            assert_eq!(w.fake.requests().len(), 2);
        },
    )
    .await;
}

#[tokio::test]
#[serial]
async fn explain_prompt_redacted_and_never_names_resource() {
    serve_with(
        |c| c.opsagent = Some(opsagent_brain::config::OpsAgentConnection::anthropic(KEY)),
        |req, ctx| async move {
            let w = World::new(req, ctx, vec![step("ok")]).await;
            let ident = "arn:aws:s3:::alpha-bucket";
            let raw = "alpha-bucket key AKIAIOSFODNN7EXAMPLE and arn:aws:s3:::alpha-bucket";
            let id = w.seen(ident, &[raw]).await;
            assert_eq!(w.post(id).await.status_code(), 200);
            let reqs = w.fake.requests();
            let r = &reqs[0];
            assert!(r.tools.is_empty() && r.max_tokens == 600);
            let user = format!("{:?}", r.messages);
            for gone in ["AKIA", "alpha-bucket", ident] {
                assert!(!user.contains(gone), "{gone} in {user}");
                assert!(!r.system.contains(gone));
            }
            assert!(
                user.contains("<untrusted source=\\\"evidence\\\">"),
                "{user}"
            );
            assert!(user.contains("[redacted:aws_key_id]"));
            assert!(!r.system.contains("redacted"));
            assert!(r.system.contains("What it means"));
        },
    )
    .await;
}

#[tokio::test]
#[serial]
async fn explain_expired_evidence_uses_empty_hash() {
    serve_with(
        |c| c.opsagent = Some(opsagent_brain::config::OpsAgentConnection::anthropic(KEY)),
        |req, ctx| async move {
            let w = World::new(req, ctx, vec![step("empty")]).await;
            let ident = "arn:aws:s3:::alpha-bucket";
            let a = w.seen(ident, &["public ACL"]).await;
            let b = w.seen("arn:aws:s3:::beta-bucket", &["other"]).await;
            w.expire_evidence(a).await;
            w.expire_evidence(b).await;
            assert_eq!(w.post(a).await.status_code(), 200);
            assert_eq!(w.post(b).await.status_code(), 200);
            assert_eq!(w.fake.requests().len(), 1);
            let hash = evidence_hash(CHECK, "", ident, &[]);
            let got = Pg::new(&w.ctx.db).explanation(w.org_id, CHECK, &hash).await;
            assert!(got.unwrap().is_some());
        },
    )
    .await;
}

#[tokio::test]
#[serial]
async fn explain_null_hash_computed_on_first_explain() {
    serve_with(
        |c| c.opsagent = Some(opsagent_brain::config::OpsAgentConnection::anthropic(KEY)),
        |req, ctx| async move {
            let w = World::new(req, ctx, vec![step("hashed")]).await;
            let ident = "arn:aws:s3:::alpha-bucket";
            let id = w.seen(ident, &["public ACL", "public policy"]).await;
            let mut f = w.finding(ident).await.into_active_model();
            f.evidence_hash = Set(None);
            f.update(&w.ctx.db).await.unwrap();
            assert_eq!(w.post(id).await.status_code(), 200);
            let want = evidence_hash(
                CHECK,
                "",
                ident,
                &["public ACL".into(), "public policy".into()],
            );
            assert_eq!(w.finding(ident).await.evidence_hash, Some(want));
        },
    )
    .await;
}

#[tokio::test]
#[serial]
async fn explain_ai_disabled_no_provider_call() {
    serve_with(
        |c| c.opsagent = Some(opsagent_brain::config::OpsAgentConnection::anthropic(KEY)),
        |req, ctx| async move {
            let w = World::new(req, ctx, vec![step("cached")]).await;
            let id = w.seen("arn:aws:s3:::alpha-bucket", &["public ACL"]).await;
            assert_eq!(w.post(id).await.status_code(), 200);
            assert_eq!(w.on(false).await, 200);
            let other = w.seen("arn:aws:s3:::beta-bucket", &["different"]).await;
            for target in [id, other] {
                let res = w.post(target).await;
                assert_eq!(res.status_code(), 409);
                assert_eq!(res.json::<Value>()["code"], "ai_disabled");
            }
            // The cached text stays readable while AI is off.
            assert_eq!(w.req.get(&w.url(id)).await.status_code(), 200);
            assert_eq!(w.fake.requests().len(), 1);
        },
    )
    .await;
}

#[tokio::test]
#[serial]
async fn explain_dark_is_ai_unavailable() {
    serve(|req, ctx| async move {
        let w = World::new(req, ctx, vec![step("never")]).await;
        let id = w.seen("arn:aws:s3:::alpha-bucket", &["public ACL"]).await;
        let res = w.post(id).await;
        assert_eq!(res.status_code(), 503);
        assert_eq!(res.json::<Value>()["code"], "ai_unavailable");
        assert!(w.fake.requests().is_empty());
    })
    .await;
}

#[tokio::test]
#[serial]
async fn explain_other_org_404() {
    serve_with(
        |c| c.opsagent = Some(opsagent_brain::config::OpsAgentConnection::anthropic(KEY)),
        |req, ctx| async move {
            let w = World::new(req, ctx, vec![step("x")]).await;
            let id = w.seen("arn:aws:s3:::alpha-bucket", &["public ACL"]).await;
            assert_eq!(w.post(id).await.status_code(), 200);
            let mail = prepare(&w.ctx);
            sign_out(&w.req, &w.csrf).await;
            let t = sign_in(&w.req, &mail, "other@example.com").await;
            let org = slug(&create_org(&w.req, &t, "Other").await);
            let url = format!("/v1/orgs/{org}/findings/{id}/explanation");
            assert_eq!(w.req.get(&url).await.status_code(), 404);
            let post = w.req.post(&url).add_header("X-CSRF-Token", &t).await;
            assert_eq!(post.status_code(), 404);
            assert_eq!(w.fake.requests().len(), 1);
        },
    )
    .await;
}

#[tokio::test]
#[serial]
async fn get_explanation_404_until_generated() {
    serve_with(
        |c| c.opsagent = Some(opsagent_brain::config::OpsAgentConnection::anthropic(KEY)),
        |req, ctx| async move {
            let w = World::new(req, ctx, vec![step("text")]).await;
            let id = w.seen("arn:aws:s3:::alpha-bucket", &["public ACL"]).await;
            assert_eq!(w.req.get(&w.url(id)).await.status_code(), 404);
            let no_csrf = w.req.post(&w.url(id)).await;
            assert_eq!(no_csrf.status_code(), 403);
            assert_eq!(w.post(id).await.status_code(), 200);
            let got: Value = w.req.get(&w.url(id)).await.json();
            assert_eq!(got["text"], "text");
        },
    )
    .await;
}

#[tokio::test]
#[serial]
async fn finding_detail_carries_cached_explanation() {
    serve_with(
        |c| c.opsagent = Some(opsagent_brain::config::OpsAgentConnection::anthropic(KEY)),
        |req, ctx| async move {
            let w = World::new(req, ctx, vec![step("text")]).await;
            let id = w.seen("arn:aws:s3:::alpha-bucket", &["public ACL"]).await;
            let detail = || async {
                let url = format!("/v1/orgs/{}/findings/{id}", w.org);
                w.req.get(&url).await.json::<Value>()
            };
            assert_eq!(detail().await["explanation"], Value::Null);
            w.post(id).await;
            let d = detail().await;
            assert_eq!(d["explanation"]["text"], "text");
            assert_eq!(d["explanation"]["label"], "Generated by AI: may be wrong");
        },
    )
    .await;
}

#[tokio::test]
#[serial]
async fn explain_sends_only_latest_run_evidence() {
    serve_with(
        |c| c.opsagent = Some(opsagent_brain::config::OpsAgentConnection::anthropic(KEY)),
        |req, ctx| async move {
            let w = World::new(req, ctx, vec![step("ok")]).await;
            let ident = "arn:aws:s3:::alpha-bucket";
            w.seen(ident, &["older run says public ACL"]).await;
            let id = w.seen(ident, &["newer run says public policy"]).await;
            assert_eq!(w.post(id).await.status_code(), 200);
            let user = format!("{:?}", w.fake.requests()[0].messages);
            assert!(user.contains("newer run says public policy"), "{user}");
            assert!(!user.contains("older run"), "{user}");
        },
    )
    .await;
}

#[tokio::test]
#[serial]
async fn explain_title_and_next_step_redacted() {
    serve_with(
        |c| c.opsagent = Some(opsagent_brain::config::OpsAgentConnection::anthropic(KEY)),
        |req, ctx| async move {
            let w = World::new(req, ctx, vec![step("ok")]).await;
            let ident = "arn:aws:s3:::alpha-bucket";
            let id = w.seen(ident, &["public ACL"]).await;
            let mut f = w.finding(ident).await.into_active_model();
            f.title = Set("Key AKIAIOSFODNN7EXAMPLE is exposed".into());
            f.next_step = Set(Some("Rotate password=hunter2hunter2".into()));
            f.update(&w.ctx.db).await.unwrap();
            assert_eq!(w.post(id).await.status_code(), 200);
            let user = format!("{:?}", w.fake.requests()[0].messages);
            for gone in ["AKIA", "hunter2"] {
                assert!(!user.contains(gone), "{gone} in {user}");
            }
        },
    )
    .await;
}

#[tokio::test]
#[serial]
async fn explain_json_evidence_redacted_per_leaf_and_by_key() {
    serve_with(
        |c| c.opsagent = Some(opsagent_brain::config::OpsAgentConnection::anthropic(KEY)),
        |req, ctx| async move {
            let w = World::new(req, ctx, vec![step("ok")]).await;
            let ident = "arn:aws:s3:::alpha-bucket";
            // Escaped quotes hide the first from text redaction; storage redacts as text.
            let raw = r#"{"env":"aws_secret_access_key=\"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"","password":"hunter2hunter2"}"#;
            let id = w.seen(ident, &[raw]).await;
            assert_eq!(w.post(id).await.status_code(), 200);
            let user = format!("{:?}", w.fake.requests()[0].messages);
            for gone in ["wJalrXUtnFEMI", "hunter2"] {
                assert!(!user.contains(gone), "{gone} in {user}");
            }
        },
    )
    .await;
}
