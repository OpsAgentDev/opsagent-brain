//! `AiAccess` and BYOK over `MemStore` and `FakeModels`.
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use opsagent_core::{
    ai::{AiRepo, KeySource, KeyStatus, ModelRole, Purpose, RoleModels, Slot, UsageRow},
    billing::{BillingRepo, BillingStatus, SubscriptionState, Tier},
    model::{
        AiProvider, Endpoint, ModelError, ModelInfo, ModelProvider, ModelRequest, ModelTurn,
        TextSink, Usage,
    },
};
use sea_orm::prelude::Decimal;

use super::*;
use crate::{
    actions::{
        orgs::{
            test_support::{kek, owned_org, scope},
            OrgScope,
        },
        recipients::test_support::guard,
    },
    adapters::{
        memory::{FixedClock, MemStore},
        model::{
            fake::{FakeModels, FakeStep},
            ModelProviders,
        },
    },
    config::{MODEL_CHAT, MODEL_ROUTINE},
    mailers::CaptureMailer,
};

const BYOK_KEY: &str = "sk-ant-api03-byok-key-abcd";
const OPSAGENT_KEY: &str = "sk-ant-opsagent-key";

/// The fake, with every API key it was called with.
struct Spy {
    fake: FakeModels,
    keys: Mutex<Vec<String>>,
}

#[async_trait]
impl ModelProvider for Spy {
    async fn stream(
        &self,
        ep: &Endpoint<'_>,
        req: &ModelRequest,
        sink: &mut dyn TextSink,
    ) -> Result<ModelTurn, ModelError> {
        self.keys.lock().unwrap().push(ep.api_key.into());
        self.fake.stream(ep, req, sink).await
    }

    async fn list_models(&self, ep: &Endpoint<'_>) -> Result<Vec<ModelInfo>, ModelError> {
        self.fake.list_models(ep).await
    }
}

struct Sink;
impl TextSink for Sink {
    fn delta(&mut self, _: &str) {}
}

struct Env {
    store: MemStore,
    spy: Arc<Spy>,
    mail: Arc<CaptureMailer>,
    scope: OrgScope,
    opsagent_key: bool,
}

/// 100,000 input tokens on `claude-sonnet-5-5`: 20 credits.
const TWENTY: Usage = Usage {
    input_tokens: 100_000,
    output_tokens: 0,
    cache_read_tokens: 0,
    cache_write_tokens: 0,
};

fn text() -> FakeStep {
    FakeStep::Text("answer".into(), TWENTY)
}

fn dec(n: i64) -> Decimal {
    Decimal::from(n)
}

async fn env(steps: Vec<FakeStep>, opsagent_key: bool) -> Env {
    let store = MemStore::default();
    let (owner, org) = owned_org(&store, "owner@example.com", "Acme").await;
    let scope = scope(&store, &org, &owner).await;
    let spy = Arc::new(Spy {
        fake: FakeModels::scripted(steps),
        keys: Mutex::default(),
    });
    let mail = Arc::new(CaptureMailer::default());
    Env {
        store,
        spy,
        mail,
        scope,
        opsagent_key,
    }
}

impl Env {
    fn org(&self) -> uuid::Uuid {
        self.scope.organisation.id
    }

    fn access_at(&self, now: DateTime<Utc>) -> Arc<AiAccess> {
        let models: Arc<dyn ModelProvider> = self.spy.clone();
        let s = AiSettings {
            opsagent_key: self.opsagent_key.then(|| OPSAGENT_KEY.to_owned().into()),
            billing_enforced: false,
            topups: false,
            web_base_url: "https://web.test/".into(),
            backoff: vec![std::time::Duration::ZERO; 3],
            anthropic_base: "https://api.anthropic.com".into(),
            openai_base: "https://api.openai.com/v1".into(),
        };
        let uow = Arc::new(self.store.clone());
        Arc::new(AiAccess::new(
            uow.clone(),
            kek(),
            ModelProviders {
                anthropic: models.clone(),
                openai: models,
            },
            Notices::new(uow, self.mail.clone(), guard(&self.store)),
            Arc::new(FixedClock(now)),
            s,
        ))
    }

    fn access(&self) -> Arc<AiAccess> {
        self.access_at(Utc::now())
    }

    async fn enable(&self) {
        self.store.set_enabled(self.org(), true).await.unwrap();
    }

    async fn put_key(&self) {
        let put = PutKey::new(self.access());
        put.run(&self.scope, "anthropic", BYOK_KEY).await.unwrap();
    }

    async fn key_status(&self, status: KeyStatus) {
        let k = self.store.keys(self.org()).await.unwrap().primary.unwrap();
        let at = Utc::now();
        assert!(self
            .store
            .set_key_status(self.org(), k.id, status, at)
            .await
            .unwrap());
    }

    async fn used(&self, source: KeySource, credits: i64) {
        let row = UsageRow {
            organisation_id: self.org(),
            member_id: None,
            purpose: Purpose::Chat,
            provider: AiProvider::Anthropic,
            model: MODEL_CHAT.into(),
            key_source: source,
            usage: Usage::default(),
            credits: dec(credits),
            estimated: false,
            slot: None,
            base_host: None,
        };
        self.store.record_usage(&row, Decimal::ZERO).await.unwrap();
    }

    async fn call(&self, a: &AiAccess, plan: &CallPlan) -> Result<ModelTurn, AiCallError> {
        let req = ModelRequest {
            model: String::new(),
            system: "system".into(),
            messages: vec![],
            tools: vec![],
            max_tokens: 100,
        };
        a.call(&self.scope, plan, Purpose::Chat, req, &mut Sink)
            .await
    }

    fn calls(&self) -> usize {
        self.spy.fake.requests().len()
    }
}

fn code(e: AppError) -> &'static str {
    match e {
        AppError::Refused { code, .. } => code,
        e => panic!("{e:?}"),
    }
}

async fn refused_with(a: &AiAccess, org: uuid::Uuid) -> &'static str {
    code(a.plan(org, ModelRole::Chat).await.err().expect("refused"))
}

#[tokio::test]
async fn who_pays_ai_off_makes_no_call() {
    let e = env(vec![text()], true).await;
    let a = e.access();
    assert_eq!(refused_with(&a, e.org()).await, AI_DISABLED);
    assert_eq!(a.status(&e.scope).await.unwrap().state, AI_DISABLED);
    assert_eq!(e.calls(), 0);
}

#[tokio::test]
async fn who_pays_byok_ok_uses_byok_key() {
    let e = env(vec![text()], true).await;
    e.enable().await;
    e.put_key().await;
    let a = e.access();
    let plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    assert_eq!(
        (plan.source, plan.provider, plan.model.as_str()),
        (KeySource::Byok, AiProvider::Anthropic, MODEL_CHAT)
    );
    e.call(&a, &plan).await.unwrap();
    assert_eq!(*e.spy.keys.lock().unwrap(), vec![BYOK_KEY.to_owned()]);
    let rows = e.store.ai_usage_rows();
    assert_eq!(rows[0].key_source, KeySource::Byok);
    // Metered for display only: the top-up balance and the quota are untouched.
    let status = a.status(&e.scope).await.unwrap();
    assert_eq!(
        (status.used, status.byok_used_this_month),
        (dec(0), dec(20))
    );
    assert_eq!(status.source, Some(KeySource::Byok));
}

#[tokio::test]
async fn who_pays_failing_byok_never_falls_back() {
    let e = env(vec![text()], true).await;
    e.enable().await;
    e.put_key().await;
    e.key_status(KeyStatus::Failing).await;
    let a = e.access();
    assert_eq!(refused_with(&a, e.org()).await, AI_KEY_FAILING);
    assert_eq!(a.status(&e.scope).await.unwrap().state, AI_KEY_FAILING);
    assert_eq!(e.calls(), 0);
}

#[tokio::test]
async fn who_pays_outage_byok_never_falls_back() {
    let e = env(vec![text()], true).await;
    e.enable().await;
    e.put_key().await;
    e.key_status(KeyStatus::ProviderOutage).await;
    // Still tried, and only on the organisation's own key.
    let a = e.access();
    let plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    assert_eq!(plan.source, KeySource::Byok);
    assert_eq!(a.status(&e.scope).await.unwrap().state, "ready");
    e.call(&a, &plan).await.unwrap();
    assert_eq!(*e.spy.keys.lock().unwrap(), vec![BYOK_KEY.to_owned()]);
}

#[tokio::test]
async fn outage_key_next_success_clears_it() {
    let e = env(vec![FakeStep::Fail(ModelError::Outage), text()], true).await;
    e.enable().await;
    e.put_key().await;
    let a = e.access();
    let plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    assert_eq!(e.call(&a, &plan).await.unwrap_err(), AiCallError::Outage);
    let k = e.store.keys(e.org()).await.unwrap().primary.unwrap();
    assert_eq!(k.status, KeyStatus::ProviderOutage);
    let plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    e.call(&a, &plan).await.unwrap();
    let k = e.store.keys(e.org()).await.unwrap().primary.unwrap();
    assert_eq!(k.status, KeyStatus::Ok);
}

#[tokio::test]
async fn put_key_resets_status_to_ok() {
    let e = env(vec![], true).await;
    e.enable().await;
    e.put_key().await;
    e.key_status(KeyStatus::Failing).await;
    assert_eq!(refused_with(&e.access(), e.org()).await, AI_KEY_FAILING);
    e.put_key().await;
    let k = e.store.keys(e.org()).await.unwrap().primary.unwrap();
    assert_eq!(k.status, KeyStatus::Ok);
    assert!(e.access().plan(e.org(), ModelRole::Chat).await.is_ok());
}

#[tokio::test]
async fn late_outage_never_downgrades_failing() {
    let steps = vec![
        FakeStep::Fail(ModelError::Auth),
        FakeStep::Fail(ModelError::Outage),
    ];
    let e = env(steps, true).await;
    e.enable().await;
    e.put_key().await;
    let a = e.access();
    let plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    assert_eq!(
        e.call(&a, &plan).await.unwrap_err(),
        AiCallError::KeyFailing
    );
    // A call planned before the refusal ends in an outage.
    assert_eq!(e.call(&a, &plan).await.unwrap_err(), AiCallError::Outage);
    let k = e.store.keys(e.org()).await.unwrap().primary.unwrap();
    assert_eq!(k.status, KeyStatus::Failing);
    assert_eq!(refused_with(&a, e.org()).await, AI_KEY_FAILING);
}

#[tokio::test]
async fn call_rechecks_credits_before_the_provider() {
    let e = env(vec![text()], true).await;
    e.enable().await;
    e.used(KeySource::OpsAgent, 990).await;
    let a = e.access();
    let plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    // A concurrent turn spends the rest after this one was planned.
    e.used(KeySource::OpsAgent, 10).await;
    assert_eq!(
        e.call(&a, &plan).await.unwrap_err(),
        AiCallError::QuotaReached
    );
    assert_eq!(e.calls(), 0);
    assert_eq!(AiCallError::QuotaReached.code(), AI_QUOTA_REACHED);
    assert_eq!(code(AiCallError::QuotaReached.into()), AI_QUOTA_REACHED);
}

#[tokio::test]
async fn call_rechecks_byok_ceiling_before_the_provider() {
    let e = env(vec![text()], true).await;
    e.enable().await;
    e.put_key().await;
    let patch = KeyPatch {
        ceiling: Some(Some(dec(10))),
        ..Default::default()
    };
    PatchKey::new(e.access())
        .run(&e.scope, patch)
        .await
        .unwrap();
    let a = e.access();
    let plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    e.used(KeySource::Byok, 10).await;
    assert_eq!(
        e.call(&a, &plan).await.unwrap_err(),
        AiCallError::QuotaReached
    );
    assert_eq!(e.calls(), 0);
}

#[tokio::test]
async fn who_pays_opsagent_key_when_no_byok() {
    let e = env(vec![text()], true).await;
    e.enable().await;
    let a = e.access();
    let plan = a.plan(e.org(), ModelRole::Routine).await.unwrap();
    assert_eq!(
        (plan.source, plan.model.as_str(), plan.key_id),
        (KeySource::OpsAgent, MODEL_ROUTINE, None)
    );
    e.call(&a, &plan).await.unwrap();
    assert_eq!(*e.spy.keys.lock().unwrap(), vec![OPSAGENT_KEY.to_owned()]);
    assert_eq!(e.spy.fake.requests()[0].model, MODEL_ROUTINE);
}

#[tokio::test]
async fn who_pays_neither_is_ai_unavailable() {
    let e = env(vec![text()], false).await;
    e.enable().await;
    let a = e.access();
    assert_eq!(refused_with(&a, e.org()).await, AI_UNAVAILABLE);
    let s = a.status(&e.scope).await.unwrap();
    assert_eq!((s.state, s.source), (AI_UNAVAILABLE, None));
}

#[tokio::test]
async fn refused_at_zero_remaining() {
    let e = env(vec![], true).await;
    e.enable().await;
    e.used(KeySource::OpsAgent, 999).await;
    assert!(e.access().plan(e.org(), ModelRole::Chat).await.is_ok());
    e.used(KeySource::OpsAgent, 1).await;
    let a = e.access();
    assert_eq!(refused_with(&a, e.org()).await, AI_QUOTA_REACHED);
    assert_eq!(a.status(&e.scope).await.unwrap().state, AI_QUOTA_REACHED);
}

#[tokio::test]
async fn topup_used_after_period_quota() {
    let e = env(vec![text(), text()], true).await;
    e.enable().await;
    e.store
        .grant_topup(e.org(), dec(1000), "evt_1")
        .await
        .unwrap();
    e.used(KeySource::OpsAgent, 970).await;
    let a = e.access();
    // Inside the quota: the top-up is untouched.
    let plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    e.call(&a, &plan).await.unwrap();
    assert_eq!(e.store.topup_balance(e.org()).await.unwrap(), dec(1000));
    // 990 used, 20 more: 10 from the quota, 10 from the top-up.
    e.call(&a, &plan).await.unwrap();
    assert_eq!(e.store.topup_balance(e.org()).await.unwrap(), dec(990));
    // Quota spent, top-up left: still allowed.
    assert!(a.plan(e.org(), ModelRole::Chat).await.is_ok());
}

#[tokio::test]
async fn topup_survives_period_rollover() {
    let e = env(vec![], true).await;
    e.enable().await;
    e.store
        .grant_topup(e.org(), dec(500), "evt_1")
        .await
        .unwrap();
    e.used(KeySource::OpsAgent, 1000).await;
    let next_month = Utc::now() + Duration::days(32);
    let s = e.access_at(next_month).status(&e.scope).await.unwrap();
    assert_eq!(
        (s.used, s.topup_balance, s.state),
        (dec(0), dec(500), "ready")
    );
}

fn subscription(start: DateTime<Utc>) -> SubscriptionState {
    SubscriptionState {
        subscription_id: "sub_1".into(),
        status: BillingStatus::Active,
        tier: Some(Tier::Starter),
        quantity: 1,
        trial_ends_at: None,
        current_period_start: Some(start),
        current_period_end: Some(start + Duration::days(30)),
    }
}

#[tokio::test]
async fn period_resets_on_stripe_period() {
    let e = env(vec![], true).await;
    e.enable().await;
    let now = Utc::now();
    let sub = subscription(now - Duration::days(10));
    e.store
        .apply_subscription(e.org(), &sub, now - Duration::days(10))
        .await
        .unwrap();
    e.used(KeySource::OpsAgent, 1000).await;
    assert_eq!(refused_with(&e.access(), e.org()).await, AI_QUOTA_REACHED);
    // The renewal starts a new period after the usage was recorded.
    let renewed = subscription(now + Duration::seconds(1));
    e.store
        .apply_subscription(e.org(), &renewed, now)
        .await
        .unwrap();
    // Read once the renewed period holds the clock (it starts 1s after `now`).
    let after = now + Duration::seconds(2);
    let s = e.access_at(after).status(&e.scope).await.unwrap();
    assert_eq!((s.used, s.quota, s.state), (dec(0), dec(1000), "ready"));
    assert_eq!(s.period.0, now + Duration::seconds(1));
}

#[tokio::test]
async fn period_resets_on_utc_month() {
    let e = env(vec![], true).await;
    e.enable().await;
    e.used(KeySource::OpsAgent, 1000).await;
    assert_eq!(refused_with(&e.access(), e.org()).await, AI_QUOTA_REACHED);
    let next_month = Utc::now() + Duration::days(32);
    assert!(e
        .access_at(next_month)
        .plan(e.org(), ModelRole::Chat)
        .await
        .is_ok());
}

#[tokio::test]
async fn byok_never_capped_by_quota() {
    let e = env(vec![text()], true).await;
    e.enable().await;
    e.used(KeySource::OpsAgent, 5000).await;
    e.put_key().await;
    let a = e.access();
    let plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    assert_eq!(plan.source, KeySource::Byok);
    e.call(&a, &plan).await.unwrap();
}

#[tokio::test]
async fn byok_ceiling_refuses_with_quota_reached() {
    let e = env(vec![], true).await;
    e.enable().await;
    e.put_key().await;
    let patch = KeyPatch {
        ceiling: Some(Some(dec(10))),
        ..Default::default()
    };
    PatchKey::new(e.access())
        .run(&e.scope, patch)
        .await
        .unwrap();
    e.used(KeySource::Byok, 9).await;
    assert!(e.access().plan(e.org(), ModelRole::Chat).await.is_ok());
    e.used(KeySource::Byok, 1).await;
    assert_eq!(refused_with(&e.access(), e.org()).await, AI_QUOTA_REACHED);
    let negative = KeyPatch {
        ceiling: Some(Some(dec(-1))),
        ..Default::default()
    };
    let err = PatchKey::new(e.access()).run(&e.scope, negative).await;
    assert_eq!(code(err.unwrap_err()), "invalid");
}

async fn set_models(e: &Env, routine: &str, chat: &str) {
    let models = RoleModels {
        routine: routine.into(),
        chat: chat.into(),
    };
    assert!(e
        .store
        .update_key_models(e.org(), Slot::Primary, &models)
        .await
        .unwrap());
}

#[tokio::test]
async fn unpriced_byok_model_estimated() {
    let e = env(vec![text()], true).await;
    e.enable().await;
    e.put_key().await;
    set_models(&e, MODEL_ROUTINE, "claude-unpriced-9").await;
    let a = e.access();
    let plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    e.call(&a, &plan).await.unwrap();
    let row = &e.store.ai_usage_rows()[0];
    // Priced at the chat role's default, claude-sonnet-5-5: 20 credits.
    assert_eq!((row.estimated, row.credits), (true, dec(20)));
    assert_eq!(row.model, "claude-unpriced-9");
    assert!(a.status(&e.scope).await.unwrap().estimated);
}

#[tokio::test]
async fn auth_error_marks_failing_and_mails_owners_once() {
    let fail = || FakeStep::Fail(ModelError::Auth);
    let e = env(vec![fail(), fail()], true).await;
    e.enable().await;
    e.put_key().await;
    let a = e.access();
    let plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    assert_eq!(
        e.call(&a, &plan).await.unwrap_err(),
        AiCallError::KeyFailing
    );
    // A call already in flight fails too, with no second email.
    assert_eq!(
        e.call(&a, &plan).await.unwrap_err(),
        AiCallError::KeyFailing
    );
    let k = e.store.keys(e.org()).await.unwrap().primary.unwrap();
    assert_eq!(k.status, KeyStatus::Failing);
    let sent = e.mail.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].to, "owner@example.com");
    assert!(sent[0].text.contains("abcd") && sent[0].text.contains("Anthropic"));
    assert!(!sent[0].text.contains(BYOK_KEY));
    assert!(e.store.ai_usage_rows().is_empty());
}

#[tokio::test]
async fn success_clears_failing() {
    let e = env(vec![text()], true).await;
    e.enable().await;
    e.put_key().await;
    let a = e.access();
    let plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    // Another call marked the key failing while this one was planned.
    e.key_status(KeyStatus::Failing).await;
    e.call(&a, &plan).await.unwrap();
    let k = e.store.keys(e.org()).await.unwrap().primary.unwrap();
    assert_eq!(k.status, KeyStatus::Ok);
}

#[tokio::test]
async fn rate_limit_retries_three_times_then_errors() {
    let rl = || FakeStep::Fail(ModelError::RateLimited);
    let e = env(vec![rl(), rl(), rl(), rl(), rl(), rl(), rl(), text()], true).await;
    e.enable().await;
    let a = e.access();
    let plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    assert_eq!(
        e.call(&a, &plan).await.unwrap_err(),
        AiCallError::RateLimited
    );
    assert_eq!(e.calls(), 4);
    // Three 429s then an answer: the fourth try succeeds.
    e.call(&a, &plan).await.unwrap();
    assert_eq!(e.calls(), 8);
}

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn opsagent_key_failure_logs_error_and_is_unavailable() {
    let steps = vec![
        FakeStep::Fail(ModelError::Auth),
        FakeStep::Fail(ModelError::Outage),
    ];
    let e = env(steps, true).await;
    e.enable().await;
    let a = e.access();
    let plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    let buf = Buf::default();
    let sub = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer({
            let b = buf.clone();
            move || b.clone()
        })
        .finish();
    let (r1, r2) = {
        let _g = tracing::subscriber::set_default(sub);
        (e.call(&a, &plan).await, e.call(&a, &plan).await)
    };
    assert_eq!(
        (r1, r2),
        (Err(AiCallError::Unavailable), Err(AiCallError::Unavailable))
    );
    let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(
        out.contains("ERROR") && out.contains("error_code=auth"),
        "{out}"
    );
    assert!(out.contains("error_code=outage"), "{out}");
    assert!(
        !out.contains(OPSAGENT_KEY) && !out.contains("system"),
        "{out}"
    );
    assert!(e.mail.sent().is_empty());
}

#[tokio::test]
async fn byok_model_gone_falls_back_saves_default_and_mails_once() {
    let gone = || FakeStep::Fail(ModelError::ModelGone);
    let e = env(vec![gone(), text(), gone(), text()], true).await;
    e.enable().await;
    e.put_key().await;
    for _ in 0..2 {
        set_models(&e, MODEL_ROUTINE, "claude-retired-1").await;
        let a = e.access();
        let plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
        assert_eq!(plan.model, "claude-retired-1");
        e.call(&a, &plan).await.unwrap();
        let k = e.store.keys(e.org()).await.unwrap().primary.unwrap();
        assert_eq!(k.models.chat, MODEL_CHAT);
        assert_eq!(k.models.routine, MODEL_ROUTINE);
    }
    let models: Vec<_> = e.spy.fake.requests().into_iter().map(|r| r.model).collect();
    assert_eq!(
        models,
        [
            "claude-retired-1",
            MODEL_CHAT,
            "claude-retired-1",
            MODEL_CHAT
        ]
    );
    // The same model gone again is not told twice.
    let sent = e.mail.sent();
    assert_eq!(sent.len(), 1);
    assert!(sent[0].text.contains("claude-retired-1") && sent[0].text.contains(MODEL_CHAT));
    assert_eq!(e.store.ai_usage_rows()[0].model, MODEL_CHAT);
}

#[tokio::test]
async fn quota_80_and_100_mailed_once_per_period() {
    let e = env(vec![text(), text(), text()], true).await;
    e.enable().await;
    e.used(KeySource::OpsAgent, 790).await;
    let a = e.access();
    let plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    e.call(&a, &plan).await.unwrap(); // 810: 80 %
    e.call(&a, &plan).await.unwrap(); // 830: told already
    assert_eq!(e.mail.sent().len(), 1);
    assert!(e.mail.sent()[0].subject.contains("80%"));
    e.used(KeySource::OpsAgent, 160).await;
    e.call(&a, &plan).await.unwrap(); // 1010: 100 %
    let sent = e.mail.sent();
    assert_eq!(sent.len(), 2);
    assert!(
        sent[1].text.contains("https://web.test/settings/ai"),
        "{}",
        sent[1].text
    );
    assert!(sent[1].subject.contains("used up"));
}

#[tokio::test]
async fn ai_call_audit_has_no_content() {
    let e = env(vec![text()], true).await;
    e.enable().await;
    let a = e.access();
    let plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    e.call(&a, &plan).await.unwrap();
    let calls: Vec<_> = e
        .store
        .audit_entries()
        .into_iter()
        .filter(|x| x.action == "ai.call")
        .collect();
    assert_eq!(calls.len(), 1);
    let meta = &calls[0].meta;
    let mut keys: Vec<_> = meta.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(keys, ["credits", "key_source", "model", "purpose"]);
    assert_eq!(
        (
            meta["purpose"].as_str(),
            meta["model"].as_str(),
            meta["credits"].as_str()
        ),
        (Some("chat"), Some(MODEL_CHAT), Some("20.00"))
    );
    assert_eq!(meta["key_source"], "opsagent");
    let text = calls[0].meta.to_string();
    assert!(!text.contains("answer") && !text.contains("system"));
}

#[tokio::test]
async fn put_key_checks_shape_before_any_call() {
    let e = env(vec![], true).await;
    let put = PutKey::new(e.access());
    for (p, k) in [
        ("anthropic", "sk-wrong-prefix-0000000"),
        ("openai", "pk-123456789012345678"),
        ("anthropic", "sk-ant-short"),
    ] {
        let err = put.run(&e.scope, p, k).await.unwrap_err();
        assert_eq!(code(err), AI_KEY_INVALID, "{k}");
    }
    assert_eq!(
        code(put.run(&e.scope, "gemini", BYOK_KEY).await.unwrap_err()),
        "invalid"
    );
    assert!(e.store.keys(e.org()).await.unwrap().primary.is_none());
}

#[tokio::test]
async fn outage_mailed_once_after_two_hours() {
    let out = || FakeStep::Fail(ModelError::Outage);
    let e = env(vec![out(), out(), out()], true).await;
    e.enable().await;
    e.put_key().await;
    let now = Utc::now();
    let plan = e
        .access_at(now)
        .plan(e.org(), ModelRole::Chat)
        .await
        .unwrap();
    let r = e.call(&e.access_at(now), &plan).await;
    assert_eq!(r.unwrap_err(), AiCallError::Outage);
    let k = e.store.keys(e.org()).await.unwrap().primary.unwrap();
    assert_eq!(k.status, KeyStatus::ProviderOutage);
    assert!(e.mail.sent().is_empty());
    let later = e.access_at(now + Duration::hours(3));
    for _ in 0..2 {
        assert_eq!(
            e.call(&later, &plan).await.unwrap_err(),
            AiCallError::Outage
        );
    }
    assert_eq!(e.mail.sent().len(), 1);
}
