use chrono::{DateTime, Duration, Utc};
use opsagent_core::{
    ai::{
        Explanation, KeySource, KeyStatus, NewModelKey, OrgKeys, Purpose, RoleModels, Slot,
        UsageRow,
    },
    model::{AiProvider, Usage},
    repo::RepoError,
};
use sea_orm::prelude::Decimal;
use uuid::Uuid;

use super::connections::org;
use super::contract_suite;

/// Whole seconds, so instants survive Postgres' microsecond timestamps unchanged.
fn now() -> DateTime<Utc> {
    DateTime::from_timestamp(Utc::now().timestamp(), 0).unwrap()
}

fn dec(s: &str) -> Decimal {
    s.parse().unwrap()
}

fn models(routine: &str, chat: &str) -> RoleModels {
    RoleModels {
        routine: routine.into(),
        chat: chat.into(),
    }
}

fn new_key(provider: AiProvider, last4: &str) -> NewModelKey {
    NewModelKey {
        provider,
        last4: last4.into(),
        models: models("small", "big"),
        slot: Slot::Primary,
        base_url: None,
        ciphertext: vec![1, 2, 3],
        nonce: vec![4, 5],
        kek_version: 1,
    }
}

fn usage(o: Uuid, source: KeySource, credits: &str) -> UsageRow {
    UsageRow {
        organisation_id: o,
        member_id: None,
        purpose: Purpose::Chat,
        provider: AiProvider::Anthropic,
        model: "claude-sonnet-5-5".into(),
        key_source: source,
        usage: Usage {
            input_tokens: 1200,
            output_tokens: 300,
            cache_read_tokens: 10,
            cache_write_tokens: 5,
        },
        credits: dec(credits),
        estimated: false,
        slot: None,
        base_host: None,
    }
}

fn explanation(hash: &str, text: &str) -> Explanation {
    Explanation {
        check_id: "s3_public".into(),
        evidence_hash: hash.into(),
        provider: AiProvider::Anthropic,
        model: "claude-haiku-5-5".into(),
        text: text.into(),
        created_at: now(),
    }
}

contract_suite! {
    async fn ai_enabled_defaults_false_and_toggles(s) {
        let (o, other) = (org(s).await, org(s).await);
        assert!(!s.ai().enabled(o).await.unwrap());
        s.ai().set_enabled(o, true).await.unwrap();
        assert!(s.ai().enabled(o).await.unwrap());
        assert!(!s.ai().enabled(other).await.unwrap());
        s.ai().set_enabled(o, false).await.unwrap();
        assert!(!s.ai().enabled(o).await.unwrap());
        let missing = Uuid::new_v4();
        assert!(matches!(s.ai().enabled(missing).await, Err(RepoError::NotFound)));
        assert!(matches!(s.ai().set_enabled(missing, true).await, Err(RepoError::NotFound)));
    }

    async fn put_key_upserts_per_slot(s) {
        let (o, other) = (org(s).await, org(s).await);
        let ai = s.ai();
        assert_eq!(ai.keys(o).await.unwrap(), OrgKeys::default());
        let first = ai.put_key(o, &new_key(AiProvider::OpenAi, "1111")).await.unwrap();
        assert_eq!((first.organisation_id, first.status, first.slot), (o, KeyStatus::Ok, Slot::Primary));
        assert_eq!(ai.keys(o).await.unwrap().primary.as_ref(), Some(&first));
        let mut b = new_key(AiProvider::Anthropic, "3333");
        (b.slot, b.base_url) = (Slot::Backup, Some("https://llm.example.com/v1".into()));
        let backup = ai.put_key(o, &b).await.unwrap();
        assert_eq!((backup.slot, backup.base_url.as_deref()), (Slot::Backup, Some("https://llm.example.com/v1")));
        let both = ai.keys(o).await.unwrap();
        assert_eq!((both.get(Slot::Primary), both.get(Slot::Backup)), (Some(&first), Some(&backup)));
        // A second primary replaces the first and leaves the backup alone.
        let at = now();
        assert!(ai.set_key_status(o, first.id, KeyStatus::Failing, at).await.unwrap());
        let second = ai.put_key(o, &new_key(AiProvider::Anthropic, "2222")).await.unwrap();
        assert_ne!(second.id, first.id);
        assert_eq!((second.provider, second.last4.as_str(), second.status), (AiProvider::Anthropic, "2222", KeyStatus::Ok));
        assert_eq!((second.ciphertext.as_slice(), second.nonce.as_slice()), (&[1u8, 2, 3][..], &[4u8, 5][..]));
        let both = ai.keys(o).await.unwrap();
        assert_eq!((both.primary.as_ref(), both.backup.as_ref()), (Some(&second), Some(&backup)));
        assert_eq!(ai.keys(other).await.unwrap(), OrgKeys::default());
        assert!(ai.put_key(Uuid::new_v4(), &new_key(AiProvider::OpenAi, "9999")).await.is_err());
    }

    async fn delete_primary_promotes_backup(s) {
        let (o, other) = (org(s).await, org(s).await);
        let ai = s.ai();
        assert!(!ai.delete_key(o, Slot::Primary).await.unwrap());
        assert!(!ai.delete_key(other, Slot::Backup).await.unwrap());
        ai.put_key(o, &new_key(AiProvider::OpenAi, "1111")).await.unwrap();
        let mut b = new_key(AiProvider::Anthropic, "3333");
        b.slot = Slot::Backup;
        let backup = ai.put_key(o, &b).await.unwrap();
        assert!(ai.delete_key(o, Slot::Primary).await.unwrap());
        let keys = ai.keys(o).await.unwrap();
        assert_eq!(keys.primary.as_ref().map(|k| (k.id, k.slot)), Some((backup.id, Slot::Primary)));
        assert_eq!(keys.backup, None);
        // A new primary now replaces the promoted one: no orphan backup.
        let again = ai.put_key(o, &new_key(AiProvider::OpenAi, "4444")).await.unwrap();
        let keys = ai.keys(o).await.unwrap();
        assert_eq!((keys.primary.map(|k| k.id), keys.backup), (Some(again.id), None));
        assert!(ai.delete_key(o, Slot::Primary).await.unwrap());
        assert!(!ai.delete_key(o, Slot::Primary).await.unwrap());
        assert_eq!(ai.keys(o).await.unwrap(), OrgKeys::default());
    }

    async fn delete_backup_keeps_primary(s) {
        let o = org(s).await;
        let ai = s.ai();
        let primary = ai.put_key(o, &new_key(AiProvider::OpenAi, "1111")).await.unwrap();
        assert!(!ai.delete_key(o, Slot::Backup).await.unwrap());
        let mut b = new_key(AiProvider::Anthropic, "3333");
        b.slot = Slot::Backup;
        ai.put_key(o, &b).await.unwrap();
        assert!(ai.delete_key(o, Slot::Backup).await.unwrap());
        let keys = ai.keys(o).await.unwrap();
        assert_eq!((keys.primary, keys.backup), (Some(primary), None));
    }

    async fn update_key_models_per_slot(s) {
        let (o, other) = (org(s).await, org(s).await);
        let ai = s.ai();
        assert!(!ai.update_key_models(o, Slot::Primary, &models("a", "b")).await.unwrap());
        ai.put_key(o, &new_key(AiProvider::OpenAi, "1111")).await.unwrap();
        assert!(!ai.update_key_models(o, Slot::Backup, &models("a", "b")).await.unwrap());
        assert!(ai.update_key_models(o, Slot::Primary, &models("a", "b")).await.unwrap());
        assert!(!ai.update_key_models(other, Slot::Primary, &models("a", "b")).await.unwrap());
        let mut b = new_key(AiProvider::Anthropic, "3333");
        b.slot = Slot::Backup;
        ai.put_key(o, &b).await.unwrap();
        assert!(ai.update_key_models(o, Slot::Backup, &models("c", "d")).await.unwrap());
        let keys = ai.keys(o).await.unwrap();
        assert_eq!(keys.primary.unwrap().models, models("a", "b"));
        assert_eq!(keys.backup.unwrap().models, models("c", "d"));
    }

    async fn credit_ceiling_round_trips(s) {
        let (o, other) = (org(s).await, org(s).await);
        let ai = s.ai();
        assert_eq!(ai.credit_ceiling(o).await.unwrap(), None);
        ai.set_credit_ceiling(o, Some(dec("50.00"))).await.unwrap();
        assert_eq!(ai.credit_ceiling(o).await.unwrap(), Some(dec("50")));
        assert_eq!(ai.credit_ceiling(other).await.unwrap(), None);
        ai.set_credit_ceiling(o, None).await.unwrap();
        assert_eq!(ai.credit_ceiling(o).await.unwrap(), None);
        let missing = Uuid::new_v4();
        assert!(matches!(ai.credit_ceiling(missing).await, Err(RepoError::NotFound)));
        assert!(matches!(ai.set_credit_ceiling(missing, None).await, Err(RepoError::NotFound)));
    }

    async fn record_usage_stores_slot_and_host(s, seed) {
        let o = org(s).await;
        let mut row = usage(o, KeySource::Byok, "1");
        (row.slot, row.base_host) = (Some(Slot::Backup), Some("llm.example.com".into()));
        s.ai().record_usage(&row, Decimal::ZERO).await.unwrap();
        s.ai().record_usage(&usage(o, KeySource::Byok, "2"), Decimal::ZERO).await.unwrap();
        // Memory returns what it stored; Postgres is read back through its own columns.
        assert_eq!(seed.usage_slots(o).await, vec![(Some(Slot::Backup), Some("llm.example.com".to_string())), (None, None)]);
    }

    async fn set_key_status_reports_transition_once(s) {
        let (o, other) = (org(s).await, org(s).await);
        let k = s.ai().put_key(o, &new_key(AiProvider::OpenAi, "1111")).await.unwrap();
        let (t1, t2) = (now() + Duration::minutes(1), now() + Duration::minutes(2));
        let ai = s.ai();
        assert!(!ai.set_key_status(o, k.id, KeyStatus::Ok, t1).await.unwrap());
        assert!(ai.set_key_status(o, k.id, KeyStatus::ProviderOutage, t1).await.unwrap());
        assert!(!ai.set_key_status(o, k.id, KeyStatus::ProviderOutage, t2).await.unwrap());
        let got = ai.keys(o).await.unwrap().primary.unwrap();
        assert_eq!((got.status, got.status_since), (KeyStatus::ProviderOutage, t1));
        // Another organisation or an unknown key id changes nothing.
        assert!(!ai.set_key_status(other, k.id, KeyStatus::Ok, t2).await.unwrap());
        assert!(!ai.set_key_status(o, Uuid::new_v4(), KeyStatus::Ok, t2).await.unwrap());
        assert!(ai.set_key_status(o, k.id, KeyStatus::Ok, t2).await.unwrap());
        let got = ai.keys(o).await.unwrap().primary.unwrap();
        assert_eq!((got.status, got.status_since), (KeyStatus::Ok, t2));
    }

    async fn record_usage_debits_topup_balance(s) {
        let (o, other) = (org(s).await, org(s).await);
        assert_eq!(s.ai().topup_balance(o).await.unwrap(), Decimal::ZERO);
        assert!(s.ai().grant_topup(o, dec("1000"), "evt_1").await.unwrap());
        assert!(s.ai().grant_topup(other, dec("1000"), "evt_2").await.unwrap());
        s.ai().record_usage(&usage(o, KeySource::OpsAgent, "12.5"), dec("2.25")).await.unwrap();
        assert_eq!(s.ai().topup_balance(o).await.unwrap(), dec("997.75"));
        s.ai().record_usage(&usage(o, KeySource::OpsAgent, "1"), Decimal::ZERO).await.unwrap();
        assert_eq!(s.ai().topup_balance(o).await.unwrap(), dec("997.75"));
        // An overshoot empties the balance; it never goes below zero.
        s.ai().record_usage(&usage(o, KeySource::OpsAgent, "2000"), dec("1500")).await.unwrap();
        assert_eq!(s.ai().topup_balance(o).await.unwrap(), Decimal::ZERO);
        assert_eq!(s.ai().topup_balance(other).await.unwrap(), dec("1000"));
        let day = (now() - Duration::days(1), now() + Duration::days(1));
        let used = s.ai().credits_used(o, KeySource::OpsAgent, day.0, day.1).await.unwrap();
        assert_eq!(used, dec("2013.5"));
    }

    async fn credits_used_filters_source_and_period(s) {
        let (o, other) = (org(s).await, org(s).await);
        let ai = s.ai();
        ai.record_usage(&usage(o, KeySource::OpsAgent, "1.25"), Decimal::ZERO).await.unwrap();
        ai.record_usage(&usage(o, KeySource::OpsAgent, "2"), Decimal::ZERO).await.unwrap();
        let mut byok = usage(o, KeySource::Byok, "7");
        (byok.member_id, byok.purpose, byok.estimated) = (Some(Uuid::new_v4()), Purpose::Explain, true);
        ai.record_usage(&byok, Decimal::ZERO).await.unwrap();
        ai.record_usage(&usage(other, KeySource::OpsAgent, "100"), Decimal::ZERO).await.unwrap();
        let (from, to) = (now() - Duration::hours(1), now() + Duration::hours(1));
        assert_eq!(ai.credits_used(o, KeySource::OpsAgent, from, to).await.unwrap(), dec("3.25"));
        assert_eq!(ai.credits_used(o, KeySource::Byok, from, to).await.unwrap(), dec("7"));
        let later = (to, to + Duration::hours(1));
        assert_eq!(ai.credits_used(o, KeySource::OpsAgent, later.0, later.1).await.unwrap(), Decimal::ZERO);
        let earlier = (from - Duration::hours(1), from);
        assert_eq!(ai.credits_used(o, KeySource::OpsAgent, earlier.0, earlier.1).await.unwrap(), Decimal::ZERO);
    }

    async fn grant_topup_idempotent_on_event(s) {
        let o = org(s).await;
        assert!(s.ai().grant_topup(o, dec("1000"), "evt_a").await.unwrap());
        assert!(!s.ai().grant_topup(o, dec("1000"), "evt_a").await.unwrap());
        assert_eq!(s.ai().topup_balance(o).await.unwrap(), dec("1000"));
        assert!(s.ai().grant_topup(o, dec("1000"), "evt_b").await.unwrap());
        assert_eq!(s.ai().topup_balance(o).await.unwrap(), dec("2000"));
    }

    async fn put_explanation_keeps_first(s) {
        let (o, other) = (org(s).await, org(s).await);
        assert_eq!(s.ai().explanation(o, "s3_public", "h1").await.unwrap(), None);
        let first = explanation("h1", "first");
        assert_eq!(s.ai().put_explanation(o, &first).await.unwrap(), first);
        let again = s.ai().put_explanation(o, &explanation("h1", "second")).await.unwrap();
        assert_eq!(again, first);
        assert_eq!(s.ai().explanation(o, "s3_public", "h1").await.unwrap(), Some(first));
        assert_eq!(s.ai().explanation(o, "s3_public", "h2").await.unwrap(), None);
        assert_eq!(s.ai().explanation(o, "s3_acl", "h1").await.unwrap(), None);
        assert_eq!(s.ai().explanation(other, "s3_public", "h1").await.unwrap(), None);
        let theirs = explanation("h1", "theirs");
        assert_eq!(s.ai().put_explanation(other, &theirs).await.unwrap(), theirs);
    }

    async fn concurrent_put_explanation_keeps_one(s) {
        let o = org(s).await;
        let (a, b) = (explanation("h", "a"), explanation("h", "b"));
        let (x, y) = tokio::join!(s.ai().put_explanation(o, &a), s.ai().put_explanation(o, &b));
        let (x, y) = (x.unwrap(), y.unwrap());
        assert_eq!(x, y);
        assert!(x == a || x == b);
        assert_eq!(s.ai().explanation(o, "s3_public", "h").await.unwrap(), Some(x));
    }

    async fn notice_once_true_once(s) {
        let (o, other) = (org(s).await, org(s).await);
        assert!(s.ai().notice_once(o, "quota80:2026-10-01").await.unwrap());
        assert!(!s.ai().notice_once(o, "quota80:2026-10-01").await.unwrap());
        assert!(s.ai().notice_once(o, "quota100:2026-10-01").await.unwrap());
        assert!(s.ai().notice_once(other, "quota80:2026-10-01").await.unwrap());
    }
}
