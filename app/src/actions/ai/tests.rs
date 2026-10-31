//! `AiAccess` and BYOK over `MemStore` and `FakeModels`.
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use opsagent_core::{
    ai::{
        AiRepo, KeySource, KeyStatus, ModelRole, NewModelKey, Purpose, RoleModels, Slot, UsageRow,
    },
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
        memory::{FixedClock, FixedResolver, MemStore},
        model::{
            fake::{FakeModels, FakeStep},
            ModelProviders,
        },
    },
    config::{MODEL_CHAT, MODEL_ROUTINE},
    creds::Dek,
    mailers::CaptureMailer,
};

const BYOK_KEY: &str = "sk-ant-api03-byok-key-abcd";
const BACKUP_KEY: &str = "sk-ant-api03-backup-key-wxyz";
const OPSAGENT_KEY: &str = "sk-ant-opsagent-key";
const OPSAGENT_BACKUP_KEY: &str = "sk-ant-opsagent-backup";

/// One model call the fake received: `(api_key, base_url, pin)`.
type Call = (String, String, Vec<SocketAddr>);

/// The fake, with every endpoint it was called on; `list` scripts `list_models`.
struct Spy {
    fake: FakeModels,
    calls: Mutex<Vec<Call>>,
    list: Option<Result<Vec<ModelInfo>, ModelError>>,
}

impl Spy {
    fn keys(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|c| c.0.clone())
            .collect()
    }

    fn calls_with(&self, key: &str) -> usize {
        self.keys().iter().filter(|k| *k == key).count()
    }
}

#[async_trait]
impl ModelProvider for Spy {
    async fn stream(
        &self,
        ep: &Endpoint<'_>,
        req: &ModelRequest,
        sink: &mut dyn TextSink,
    ) -> Result<ModelTurn, ModelError> {
        let call = (ep.api_key.into(), ep.base_url.into(), ep.pin.to_vec());
        self.calls.lock().unwrap().push(call);
        self.fake.stream(ep, req, sink).await
    }

    async fn list_models(&self, ep: &Endpoint<'_>) -> Result<Vec<ModelInfo>, ModelError> {
        match &self.list {
            Some(l) => l.clone(),
            None => self.fake.list_models(ep).await,
        }
    }
}

/// Counts the deltas it got.
#[derive(Default)]
struct Sink(usize);
impl TextSink for Sink {
    fn delta(&mut self, _: &str) {
        self.0 += 1;
    }
}

struct Env {
    store: MemStore,
    spy: Arc<Spy>,
    mail: Arc<CaptureMailer>,
    scope: OrgScope,
    opsagent_key: bool,
    opsagent_backup: bool,
    /// The resolver's table, read each time an `AiAccess` is built.
    hosts: Mutex<HashMap<String, Vec<IpAddr>>>,
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
    env_listing(steps, opsagent_key, None).await
}

async fn env_listing(
    steps: Vec<FakeStep>,
    opsagent_key: bool,
    list: Option<Result<Vec<ModelInfo>, ModelError>>,
) -> Env {
    let store = MemStore::default();
    let (owner, org) = owned_org(&store, "owner@example.com", "Acme").await;
    let scope = scope(&store, &org, &owner).await;
    let spy = Arc::new(Spy {
        fake: FakeModels::scripted(steps),
        calls: Mutex::default(),
        list,
    });
    let mail = Arc::new(CaptureMailer::default());
    Env {
        store,
        spy,
        mail,
        scope,
        opsagent_key,
        opsagent_backup: false,
        hosts: Mutex::default(),
    }
}

impl Env {
    fn org(&self) -> uuid::Uuid {
        self.scope.organisation.id
    }

    fn access_at(&self, now: DateTime<Utc>) -> Arc<AiAccess> {
        let models: Arc<dyn ModelProvider> = self.spy.clone();
        let s = AiSettings {
            opsagent: None,
            opsagent_backup: None,
            anthropic_base: "https://api.anthropic.com".into(),
            openai_base: "https://api.openai.com/v1".into(),
            policy: UrlPolicy::Public,
            billing_enforced: false,
            topups: false,
            web_base_url: "https://web.test/".into(),
            backoff: vec![std::time::Duration::ZERO; 3],
        };
        let s = AiSettings {
            opsagent: self
                .opsagent_key
                .then(|| s.conn(OpsAgentConnection::anthropic(OPSAGENT_KEY), Slot::Primary)),
            opsagent_backup: self.opsagent_backup.then(|| {
                s.conn(
                    OpsAgentConnection::anthropic(OPSAGENT_BACKUP_KEY),
                    Slot::Backup,
                )
            }),
            ..s
        };
        let uow = Arc::new(self.store.clone());
        let hosts = self.hosts.lock().unwrap().clone();
        Arc::new(AiAccess::new(
            uow.clone(),
            kek(),
            ModelProviders {
                anthropic: models.clone(),
                openai: models,
            },
            Arc::new(FixedResolver::new(hosts)),
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
        let input = input("anthropic", BYOK_KEY);
        put.run(&self.scope, Slot::Primary, input).await.unwrap();
    }

    /// Stores a sealed key straight into `slot`, on `base_url` when given.
    async fn store_key(&self, slot: Slot, key: &str, base_url: Option<&str>) {
        let org = self.org();
        let dek = Dek::of(&self.store, &*kek(), org).await.unwrap();
        let sealed = dek.seal_bytes(key.as_bytes(), &aad(org));
        let new = NewModelKey {
            provider: AiProvider::Anthropic,
            last4: key[key.len() - 4..].into(),
            models: RoleModels {
                routine: MODEL_ROUTINE.into(),
                chat: MODEL_CHAT.into(),
            },
            slot,
            base_url: base_url.map(str::to_owned),
            ciphertext: sealed.ciphertext,
            nonce: sealed.nonce.to_vec(),
            kek_version: dek.version,
        };
        self.store.put_key(org, &new).await.unwrap();
    }

    async fn put_backup(&self) {
        self.store_key(Slot::Backup, BACKUP_KEY, None).await;
    }

    async fn key_status(&self, status: KeyStatus) {
        self.slot_status(Slot::Primary, status).await;
    }

    async fn slot_status(&self, slot: Slot, status: KeyStatus) {
        let keys = self.store.keys(self.org()).await.unwrap();
        let k = keys.get(slot).unwrap();
        let at = Utc::now();
        assert!(self
            .store
            .set_key_status(self.org(), k.id, status, at)
            .await
            .unwrap());
    }

    async fn status_of(&self, slot: Slot) -> KeyStatus {
        let keys = self.store.keys(self.org()).await.unwrap();
        keys.get(slot).unwrap().status
    }

    fn fell_back(&self) -> Vec<bool> {
        self.store
            .audit_entries()
            .into_iter()
            .filter(|x| x.action == "ai.call")
            .map(|x| x.meta["fell_back"].as_bool().unwrap())
            .collect()
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

    async fn call(&self, a: &AiAccess, plan: &mut CallPlan) -> Result<ModelTurn, AiCallError> {
        self.call_into(a, plan, &mut Sink::default()).await
    }

    async fn call_into(
        &self,
        a: &AiAccess,
        plan: &mut CallPlan,
        sink: &mut Sink,
    ) -> Result<ModelTurn, AiCallError> {
        let req = ModelRequest {
            model: String::new(),
            system: "system".into(),
            messages: vec![],
            tools: vec![],
            max_tokens: 100,
        };
        a.call(&self.scope, plan, Purpose::Chat, req, sink).await
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
    let mut plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    assert_eq!(
        (plan.source(), plan.provider(), plan.model()),
        (KeySource::Byok, AiProvider::Anthropic, MODEL_CHAT)
    );
    e.call(&a, &mut plan).await.unwrap();
    assert_eq!(e.spy.keys(), vec![BYOK_KEY.to_owned()]);
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
async fn who_pays_failing_byok_never_uses_opsagent_key() {
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
async fn who_pays_outage_byok_never_uses_opsagent_key() {
    let e = env(vec![text()], true).await;
    e.enable().await;
    e.put_key().await;
    e.key_status(KeyStatus::ProviderOutage).await;
    // Still tried, and only on the organisation's own key.
    let a = e.access();
    let mut plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    assert_eq!(plan.source(), KeySource::Byok);
    assert_eq!(a.status(&e.scope).await.unwrap().state, "ready");
    e.call(&a, &mut plan).await.unwrap();
    assert_eq!(e.spy.keys(), vec![BYOK_KEY.to_owned()]);
}

#[tokio::test]
async fn outage_key_next_success_clears_it() {
    let e = env(vec![FakeStep::Fail(ModelError::Outage), text()], true).await;
    e.enable().await;
    e.put_key().await;
    let a = e.access();
    let mut plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    assert_eq!(
        e.call(&a, &mut plan).await.unwrap_err(),
        AiCallError::Outage
    );
    let k = e.store.keys(e.org()).await.unwrap().primary.unwrap();
    assert_eq!(k.status, KeyStatus::ProviderOutage);
    let mut plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    e.call(&a, &mut plan).await.unwrap();
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
    let mut plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    assert_eq!(
        e.call(&a, &mut plan).await.unwrap_err(),
        AiCallError::KeyFailing
    );
    // A call planned before the refusal ends in an outage.
    assert_eq!(
        e.call(&a, &mut plan).await.unwrap_err(),
        AiCallError::Outage
    );
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
    let mut plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    // A concurrent turn spends the rest after this one was planned.
    e.used(KeySource::OpsAgent, 10).await;
    assert_eq!(
        e.call(&a, &mut plan).await.unwrap_err(),
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
    SetCeiling::new(e.access())
        .run(&e.scope, Some(dec(10)))
        .await
        .unwrap();
    let a = e.access();
    let mut plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    e.used(KeySource::Byok, 10).await;
    assert_eq!(
        e.call(&a, &mut plan).await.unwrap_err(),
        AiCallError::QuotaReached
    );
    assert_eq!(e.calls(), 0);
}

#[tokio::test]
async fn who_pays_opsagent_key_when_no_byok() {
    let e = env(vec![text()], true).await;
    e.enable().await;
    let a = e.access();
    let mut plan = a.plan(e.org(), ModelRole::Routine).await.unwrap();
    assert_eq!(
        (plan.source(), plan.model(), plan.conn.key_id),
        (KeySource::OpsAgent, MODEL_ROUTINE, None)
    );
    e.call(&a, &mut plan).await.unwrap();
    assert_eq!(e.spy.keys(), vec![OPSAGENT_KEY.to_owned()]);
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
    let mut plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    e.call(&a, &mut plan).await.unwrap();
    assert_eq!(e.store.topup_balance(e.org()).await.unwrap(), dec(1000));
    // 990 used, 20 more: 10 from the quota, 10 from the top-up.
    e.call(&a, &mut plan).await.unwrap();
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
    let mut plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    assert_eq!(plan.source(), KeySource::Byok);
    e.call(&a, &mut plan).await.unwrap();
}

#[tokio::test]
async fn byok_ceiling_refuses_with_quota_reached() {
    let e = env(vec![], true).await;
    e.enable().await;
    e.put_key().await;
    SetCeiling::new(e.access())
        .run(&e.scope, Some(dec(10)))
        .await
        .unwrap();
    e.used(KeySource::Byok, 9).await;
    assert!(e.access().plan(e.org(), ModelRole::Chat).await.is_ok());
    e.used(KeySource::Byok, 1).await;
    assert_eq!(refused_with(&e.access(), e.org()).await, AI_QUOTA_REACHED);
    let err = SetCeiling::new(e.access())
        .run(&e.scope, Some(dec(-1)))
        .await;
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
    let mut plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    e.call(&a, &mut plan).await.unwrap();
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
    let mut plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    assert_eq!(
        e.call(&a, &mut plan).await.unwrap_err(),
        AiCallError::KeyFailing
    );
    // A call already in flight fails too, with no second email.
    assert_eq!(
        e.call(&a, &mut plan).await.unwrap_err(),
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
    let mut plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    // Another call marked the key failing while this one was planned.
    e.key_status(KeyStatus::Failing).await;
    e.call(&a, &mut plan).await.unwrap();
    let k = e.store.keys(e.org()).await.unwrap().primary.unwrap();
    assert_eq!(k.status, KeyStatus::Ok);
}

#[tokio::test]
async fn rate_limit_retries_three_times_then_errors() {
    let rl = || FakeStep::Fail(ModelError::RateLimited);
    let e = env(vec![rl(), rl(), rl(), rl(), rl(), rl(), rl(), text()], true).await;
    e.enable().await;
    let a = e.access();
    let mut plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    assert_eq!(
        e.call(&a, &mut plan).await.unwrap_err(),
        AiCallError::RateLimited
    );
    assert_eq!(e.calls(), 4);
    // Three 429s then an answer: the fourth try succeeds.
    e.call(&a, &mut plan).await.unwrap();
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
    let mut plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
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
        (e.call(&a, &mut plan).await, e.call(&a, &mut plan).await)
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
        let mut plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
        assert_eq!(plan.model(), "claude-retired-1");
        e.call(&a, &mut plan).await.unwrap();
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
    let mut plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    e.call(&a, &mut plan).await.unwrap(); // 810: 80 %
    e.call(&a, &mut plan).await.unwrap(); // 830: told already
    assert_eq!(e.mail.sent().len(), 1);
    assert!(e.mail.sent()[0].subject.contains("80%"));
    e.used(KeySource::OpsAgent, 160).await;
    e.call(&a, &mut plan).await.unwrap(); // 1010: 100 %
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
    let mut plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    e.call(&a, &mut plan).await.unwrap();
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
    assert_eq!(
        keys,
        [
            "credits",
            "fell_back",
            "key_source",
            "model",
            "purpose",
            "slot"
        ]
    );
    assert_eq!(
        (meta["slot"].as_str(), &meta["fell_back"]),
        (Some("primary"), &serde_json::json!(false))
    );
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

fn input(style: &str, key: &str) -> KeyInput {
    KeyInput {
        style: style.into(),
        base_url: None,
        api_key: key.into(),
        models: None,
    }
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
        let err = put.run(&e.scope, Slot::Primary, input(p, k)).await;
        let err = err.unwrap_err();
        assert_eq!(code(err), AI_KEY_INVALID, "{k}");
    }
    assert_eq!(
        code(
            put.run(&e.scope, Slot::Primary, input("gemini", BYOK_KEY))
                .await
                .unwrap_err()
        ),
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
    let mut plan = e
        .access_at(now)
        .plan(e.org(), ModelRole::Chat)
        .await
        .unwrap();
    let r = e.call(&e.access_at(now), &mut plan).await;
    assert_eq!(r.unwrap_err(), AiCallError::Outage);
    let k = e.store.keys(e.org()).await.unwrap().primary.unwrap();
    assert_eq!(k.status, KeyStatus::ProviderOutage);
    assert!(e.mail.sent().is_empty());
    let later = e.access_at(now + Duration::hours(3));
    for _ in 0..2 {
        assert_eq!(
            e.call(&later, &mut plan).await.unwrap_err(),
            AiCallError::Outage
        );
    }
    assert_eq!(e.mail.sent().len(), 1);
}

fn fail(e: ModelError) -> FakeStep {
    FakeStep::Fail(e)
}

/// One fallback-table row: the primary's script, whether a backup exists, the code it
/// ends with (`None`: answered), primary status after, calls on primary and backup.
struct Row {
    primary: Vec<FakeStep>,
    backup: bool,
    list_unusable: bool,
    ends: Option<&'static str>,
    status: KeyStatus,
    calls: (usize, usize),
}

#[tokio::test]
async fn fallback_table() {
    let rl = || fail(ModelError::RateLimited);
    let rows = [
        Row {
            primary: vec![rl(), rl()],
            backup: true,
            list_unusable: false,
            ends: None,
            status: KeyStatus::Ok,
            calls: (2, 1),
        },
        Row {
            primary: vec![rl(), rl(), rl(), rl()],
            backup: false,
            list_unusable: false,
            ends: Some(AI_RATE_LIMITED),
            status: KeyStatus::Ok,
            calls: (4, 0),
        },
        Row {
            primary: vec![fail(ModelError::Outage)],
            backup: true,
            list_unusable: false,
            ends: None,
            status: KeyStatus::ProviderOutage,
            calls: (1, 1),
        },
        Row {
            primary: vec![fail(ModelError::Auth)],
            backup: true,
            list_unusable: false,
            ends: None,
            status: KeyStatus::Failing,
            calls: (1, 1),
        },
        Row {
            primary: vec![fail(ModelError::ModelGone)],
            backup: true,
            list_unusable: true,
            ends: None,
            status: KeyStatus::Ok,
            calls: (1, 1),
        },
        Row {
            primary: vec![fail(ModelError::ModelGone)],
            backup: false,
            list_unusable: true,
            ends: Some(AI_MODEL_INVALID),
            status: KeyStatus::Ok,
            calls: (1, 0),
        },
        Row {
            primary: vec![fail(ModelError::Other("http_400".into()))],
            backup: true,
            list_unusable: false,
            ends: Some("internal"),
            status: KeyStatus::Ok,
            calls: (1, 0),
        },
    ];
    for (i, row) in rows.into_iter().enumerate() {
        let mut steps = row.primary;
        steps.push(text());
        let list = row.list_unusable.then(|| Ok(vec![]));
        let e = env_listing(steps, true, list).await;
        e.enable().await;
        // Stored directly: `PutKey` would refuse a key whose list is empty.
        e.store_key(Slot::Primary, BYOK_KEY, None).await;
        if row.backup {
            e.put_backup().await;
        }
        let a = e.access();
        let mut plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
        let r = e.call(&a, &mut plan).await;
        assert_eq!(r.as_ref().err().map(AiCallError::code), row.ends, "row {i}");
        let calls = (e.spy.calls_with(BYOK_KEY), e.spy.calls_with(BACKUP_KEY));
        assert_eq!(calls, row.calls, "row {i}");
        assert_eq!(e.spy.calls_with(OPSAGENT_KEY), 0, "row {i}");
        assert_eq!(e.status_of(Slot::Primary).await, row.status, "row {i}");
        let rows = e.store.ai_usage_rows();
        if row.ends.is_none() {
            assert_eq!(rows.len(), 1, "row {i}");
            assert_eq!(rows[0].slot, Some(Slot::Backup), "row {i}");
            assert_eq!(e.fell_back(), [true], "row {i}");
        } else {
            assert!(rows.is_empty(), "row {i}");
        }
        if row.status == KeyStatus::Failing {
            let sent = e.mail.sent();
            assert_eq!(sent.len(), 1, "row {i}");
            assert_eq!(sent[0].subject, "Your OpsAgent AI backup key is in use");
            assert_eq!(
                sent[0].text,
                "Your Anthropic key ending abcd was refused, so Dashboard AI is using your \
                 backup key ending wxyz. Replace the primary key: https://web.test/settings/ai"
            );
        }
    }
}

#[tokio::test]
async fn no_fallback_after_first_delta() {
    let half = FakeStep::TextThenFail("half".into(), ModelError::Outage);
    let e = env(vec![half, text()], true).await;
    e.enable().await;
    e.put_key().await;
    e.put_backup().await;
    let a = e.access();
    let mut plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    let mut sink = Sink::default();
    let r = e.call_into(&a, &mut plan, &mut sink).await;
    assert_eq!(r.unwrap_err().code(), AI_PROVIDER_OUTAGE);
    assert_eq!(e.spy.calls_with(BACKUP_KEY), 0);
    assert_eq!(sink.0, 1);
    assert!(e.store.ai_usage_rows().is_empty());
}

#[tokio::test]
async fn failing_primary_with_ok_backup_answers() {
    let e = env(vec![text(), text()], true).await;
    e.enable().await;
    e.put_key().await;
    e.put_backup().await;
    e.key_status(KeyStatus::Failing).await;
    for _ in 0..2 {
        let a = e.access();
        let mut plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
        e.call(&a, &mut plan).await.unwrap();
    }
    assert_eq!(e.spy.keys(), [BACKUP_KEY, BACKUP_KEY]);
    assert_eq!(e.fell_back(), [true, true]);
    let sent = e.mail.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].subject, "Your OpsAgent AI backup key is in use");
    let s = e.access().status(&e.scope).await.unwrap();
    assert_eq!((s.state, s.source), ("ready", Some(KeySource::Byok)));
    assert!(s.keys.primary.is_some() && s.keys.backup.is_some());
}

#[tokio::test]
async fn both_failing_is_ai_key_failing() {
    // backup_never_crosses_payer: OpsAgent's key is configured and never used.
    let e = env(vec![text()], true).await;
    e.enable().await;
    e.put_key().await;
    e.put_backup().await;
    e.key_status(KeyStatus::Failing).await;
    e.slot_status(Slot::Backup, KeyStatus::Failing).await;
    let a = e.access();
    assert_eq!(refused_with(&a, e.org()).await, AI_KEY_FAILING);
    assert_eq!(a.status(&e.scope).await.unwrap().state, AI_KEY_FAILING);
    assert_eq!(e.calls(), 0);
}

#[tokio::test]
async fn opsagent_backup_used_on_auth() {
    let mut e = env(vec![fail(ModelError::Auth), text()], true).await;
    e.opsagent_backup = true;
    e.enable().await;
    let a = e.access();
    let mut plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    e.call(&a, &mut plan).await.unwrap();
    assert_eq!(e.spy.keys(), [OPSAGENT_KEY, OPSAGENT_BACKUP_KEY]);
    let rows = e.store.ai_usage_rows();
    assert_eq!(
        (rows[0].key_source, rows[0].slot),
        (KeySource::OpsAgent, Some(Slot::Backup))
    );
    assert_eq!(e.fell_back(), [true]);
}

#[tokio::test]
async fn custom_endpoint_rechecked_every_call() {
    let e = env(vec![text(), text()], true).await;
    e.enable().await;
    e.store_key(Slot::Primary, BYOK_KEY, Some("https://gw.test/v1"))
        .await;
    let public: IpAddr = "1.1.1.1".parse().unwrap();
    e.hosts
        .lock()
        .unwrap()
        .insert("gw.test".into(), vec![public]);
    let a = e.access();
    let mut plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    e.call(&a, &mut plan).await.unwrap();
    // Rebinding: the same name now answers a private address.
    let private: IpAddr = "10.0.0.1".parse().unwrap();
    e.hosts
        .lock()
        .unwrap()
        .insert("gw.test".into(), vec![private]);
    let a = e.access();
    let mut plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    let r = e.call(&a, &mut plan).await;
    assert_eq!(r.unwrap_err().code(), AI_PROVIDER_OUTAGE);
    let calls = e.spy.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1, "https://gw.test/v1");
    assert_eq!(calls[0].2, [SocketAddr::new(public, 443)]);
    assert!(calls.iter().all(|c| c.2.iter().all(|p| p.ip() != private)));
    let rows = e.store.ai_usage_rows();
    assert_eq!(rows[0].base_host.as_deref(), Some("gw.test"));
    assert_eq!(e.status_of(Slot::Primary).await, KeyStatus::ProviderOutage);
}

#[tokio::test]
async fn ceiling_counts_both_connections() {
    let e = env(vec![text()], true).await;
    e.enable().await;
    e.put_key().await;
    e.put_backup().await;
    e.store
        .set_credit_ceiling(e.org(), Some(dec(50)))
        .await
        .unwrap();
    for (slot, credits) in [(Slot::Primary, 30), (Slot::Backup, 25)] {
        let row = UsageRow {
            organisation_id: e.org(),
            member_id: None,
            purpose: Purpose::Chat,
            provider: AiProvider::Anthropic,
            model: MODEL_CHAT.into(),
            key_source: KeySource::Byok,
            usage: Usage::default(),
            credits: dec(credits),
            estimated: false,
            slot: Some(slot),
            base_host: None,
        };
        e.store.record_usage(&row, Decimal::ZERO).await.unwrap();
    }
    assert_eq!(refused_with(&e.access(), e.org()).await, AI_QUOTA_REACHED);
    assert_eq!(e.calls(), 0);
}

#[tokio::test]
async fn backup_failing_beside_working_primary_mails_once() {
    let steps = vec![fail(ModelError::Outage), fail(ModelError::Auth)];
    let e = env(steps, true).await;
    e.enable().await;
    e.put_key().await;
    e.put_backup().await;
    let a = e.access();
    let mut plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    let r = e.call(&a, &mut plan).await;
    assert_eq!(r.unwrap_err(), AiCallError::KeyFailing);
    assert_eq!(e.status_of(Slot::Primary).await, KeyStatus::ProviderOutage);
    assert_eq!(e.status_of(Slot::Backup).await, KeyStatus::Failing);
    let sent = e.mail.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].subject, "Your OpsAgent AI backup key isn't working");
    assert_eq!(
        sent[0].text,
        "Your backup Anthropic key ending wxyz was refused. Dashboard AI still runs on your \
         primary key; replace the backup key: https://web.test/settings/ai"
    );
}

#[tokio::test]
async fn both_failing_in_one_call_mails_has_stopped_only() {
    let steps = vec![fail(ModelError::Auth), fail(ModelError::Auth)];
    let e = env(steps, true).await;
    e.enable().await;
    e.put_key().await;
    e.put_backup().await;
    let a = e.access();
    let mut plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    let r = e.call(&a, &mut plan).await;
    assert_eq!(r.unwrap_err(), AiCallError::KeyFailing);
    assert_eq!(e.status_of(Slot::Primary).await, KeyStatus::Failing);
    assert_eq!(e.status_of(Slot::Backup).await, KeyStatus::Failing);
    let sent = e.mail.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].subject, "Your OpsAgent AI key is failing");
    assert!(sent[0].text.contains("has stopped"), "{}", sent[0].text);
}

#[tokio::test]
async fn model_gone_with_usable_list_replaces_on_primary_not_backup() {
    let e = env(vec![fail(ModelError::ModelGone), text()], true).await;
    e.enable().await;
    e.put_key().await;
    e.put_backup().await;
    set_models(&e, MODEL_ROUTINE, "claude-retired-1").await;
    let a = e.access();
    let mut plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    e.call(&a, &mut plan).await.unwrap();
    assert_eq!(e.spy.keys(), [BYOK_KEY, BYOK_KEY]);
    let rows = e.store.ai_usage_rows();
    assert_eq!(
        (rows[0].slot, rows[0].model.as_str()),
        (Some(Slot::Primary), MODEL_CHAT)
    );
    assert_eq!(e.fell_back(), [false]);
}

/// The log lines written while `f` runs.
async fn logs<F: std::future::Future>(f: F) -> (F::Output, String) {
    let buf = Buf::default();
    let sub = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer({
            let b = buf.clone();
            move || b.clone()
        })
        .finish();
    let out = {
        let _g = tracing::subscriber::set_default(sub);
        f.await
    };
    let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    (out, text)
}

#[tokio::test]
async fn opsagent_failure_before_backup_logs_warn() {
    // The backup answers: the primary's failure is a warning.
    let mut e = env(vec![fail(ModelError::Auth), text()], true).await;
    e.opsagent_backup = true;
    e.enable().await;
    let a = e.access();
    let mut plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    let (r, out) = logs(e.call(&a, &mut plan)).await;
    r.unwrap();
    assert!(
        out.contains("WARN") && out.contains("error_code=auth"),
        "{out}"
    );
    assert!(!out.contains("ERROR"), "{out}");
    // The backup fails too: that one is an error.
    let mut e = env(vec![fail(ModelError::Auth), fail(ModelError::Outage)], true).await;
    e.opsagent_backup = true;
    e.enable().await;
    let a = e.access();
    let mut plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    let (r, out) = logs(e.call(&a, &mut plan)).await;
    assert_eq!(r.unwrap_err(), AiCallError::Unavailable);
    assert!(
        out.contains("ERROR") && out.contains("error_code=outage"),
        "{out}"
    );
}

#[tokio::test]
async fn primary_failing_backup_outage_mails_has_stopped() {
    let steps = vec![
        fail(ModelError::Auth),
        fail(ModelError::Outage),
        fail(ModelError::Outage),
    ];
    let e = env(steps, true).await;
    e.enable().await;
    e.put_key().await;
    e.put_backup().await;
    let a = e.access();
    let mut plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    let r = e.call(&a, &mut plan).await;
    assert_eq!(r.unwrap_err(), AiCallError::Outage);
    assert_eq!(e.status_of(Slot::Primary).await, KeyStatus::Failing);
    assert_eq!(e.status_of(Slot::Backup).await, KeyStatus::ProviderOutage);
    // A later call planned on the backup fails again: no second email.
    let mut plan = a.plan(e.org(), ModelRole::Chat).await.unwrap();
    assert_eq!(
        e.call(&a, &mut plan).await.unwrap_err(),
        AiCallError::Outage
    );
    let sent = e.mail.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].subject, "Your OpsAgent AI key is failing");
    assert!(sent[0].text.contains("ending abcd") && sent[0].text.contains("has stopped"));
}

#[tokio::test]
async fn put_custom_key_stores_the_cleaned_host() {
    let e = env(vec![], false).await;
    let public: IpAddr = "1.1.1.1".parse().unwrap();
    e.hosts
        .lock()
        .unwrap()
        .insert("api.example.com".into(), vec![public]);
    let put = PutKey::new(e.access());
    let input = KeyInput {
        base_url: Some("https://API.Example.COM./v1".into()),
        ..input("anthropic", BYOK_KEY)
    };
    let out = put.run(&e.scope, Slot::Primary, input).await.unwrap();
    let stored = out.status.keys.primary.unwrap().base_url.unwrap();
    assert_eq!(stored, "https://api.example.com/v1");
    assert_eq!(host_of(&stored).as_deref(), Some("api.example.com"));
    let set = e
        .store
        .audit_entries()
        .into_iter()
        .find(|x| x.action == "ai.key.set");
    assert_eq!(set.unwrap().meta["base_host"], "api.example.com");
}

#[tokio::test]
async fn ceiling_change_is_audited() {
    let e = env(vec![], true).await;
    let set = SetCeiling::new(e.access());
    set.run(&e.scope, Some(Decimal::new(125, 1))).await.unwrap();
    set.run(&e.scope, None).await.unwrap();
    set.patch(&e.scope, Some(true), None).await.unwrap();
    let metas: Vec<_> = e
        .store
        .audit_entries()
        .into_iter()
        .filter(|x| x.action == "ai.ceiling.set")
        .map(|x| x.meta)
        .collect();
    assert_eq!(
        metas,
        vec![
            serde_json::json!({ "monthly_credit_ceiling": "12.50" }),
            serde_json::json!({ "monthly_credit_ceiling": null }),
        ]
    );
}

#[tokio::test]
async fn unreadable_backup_key_plans_without_backup() {
    let e = env(vec![text()], false).await;
    e.enable().await;
    e.store_key(Slot::Primary, BYOK_KEY, None).await;
    let org = e.org();
    let dek = Dek::of(&e.store, &*kek(), org).await.unwrap();
    let mut sealed = dek.seal_bytes(BACKUP_KEY.as_bytes(), &aad(org));
    sealed.ciphertext[0] ^= 0xff;
    let new = NewModelKey {
        provider: AiProvider::Anthropic,
        last4: "abcd".into(),
        models: RoleModels {
            routine: MODEL_ROUTINE.into(),
            chat: MODEL_CHAT.into(),
        },
        slot: Slot::Backup,
        base_url: None,
        ciphertext: sealed.ciphertext,
        nonce: sealed.nonce.to_vec(),
        kek_version: dek.version,
    };
    e.store.put_key(org, &new).await.unwrap();
    let a = e.access();
    let mut plan = a.plan(org, ModelRole::Chat).await.unwrap();
    assert!(plan.backup.is_none());
    assert_eq!(plan.conn.slot, Slot::Primary);
    e.call(&a, &mut plan).await.unwrap();
}
