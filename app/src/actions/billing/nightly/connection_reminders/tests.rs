use std::sync::Arc;

use async_trait::async_trait;
use opsagent_core::{
    billing::{BillingRepo, BillingStatus as B},
    connection::ConnectionPatch,
    org::{OrganisationsRepo, Role},
};

use super::super::tests::{night, sub, sync, sync_with};
use super::*;
use crate::{
    actions::{
        orgs::test_support::{owned_org, user},
        runs::test_support::{connected, pending},
        uow::Repos,
    },
    adapters::memory::MemStore,
    mailers::{CaptureMailer, FailingMailer, Mailer},
};

/// An organisation with an active subscription and one pending connection "Prod".
async fn world(store: &MemStore, owner: &str, name: &str) -> (Uuid, Connection) {
    let (_, org) = owned_org(store, owner, name).await;
    let c = pending(store, org.id).await;
    let s = sub(B::Active, c.created_at + Duration::days(20));
    store
        .apply_subscription(org.id, &s, c.created_at)
        .await
        .unwrap();
    (org.id, c)
}

async fn add(store: &MemStore, org: Uuid, email: &str, role: Role) {
    let u = user(store, email).await;
    store.add_member(org, u.id, role).await.unwrap();
}

/// Another pending connection of `org`, called `name`.
async fn named(store: &MemStore, org: Uuid, name: &str) -> Connection {
    let c = pending(store, org).await;
    let patch = ConnectionPatch {
        display_name: Some(name.into()),
        ..Default::default()
    };
    store.connections().update(org, c.id, patch).await.unwrap()
}

/// Fails every send to one address; the rest are captured.
struct DownFor(&'static str, Arc<CaptureMailer>);

#[async_trait]
impl Mailer for DownFor {
    async fn send(&self, mail: Mail) -> Result<(), String> {
        match mail.to == self.0 {
            true => Err("mail down".into()),
            false => self.1.send(mail).await,
        }
    }
}

fn due(name: Option<&str>, step: u8, reason: Option<&str>) -> Due {
    let now = Utc::now();
    let c = Connection {
        id: Uuid::nil(),
        organisation_id: Uuid::nil(),
        provider: "aws".into(),
        display_name: name.map(Into::into),
        status: S::Pending,
        status_reason: reason.map(Into::into),
        external_account_id: None,
        template_version: None,
        scan_time_local: None,
        briefing_time_local: None,
        api_rate_ceiling: None,
        slack_channel_id: None,
        first_connected_at: None,
        billable_from: None,
        verify_denied_streak: 0,
        verify_denied_first_at: None,
        urgent_alerts: true,
        disconnected_at: None,
        created_at: now,
        updated_at: now,
    };
    let marker = Uuid::nil();
    Due { c, step, marker }
}

fn mail_for(due: &[Due]) -> Mail {
    let due: Vec<&Due> = due.iter().collect();
    Reminder::mail(&due, "https://opsagent.test/o/acme", "o@example.com".into())
}

#[test]
fn steps() {
    let at = |h| step(Duration::hours(h));
    assert_eq!(at(23), None);
    assert_eq!((at(24), at(71)), (Some(1), Some(1)));
    assert_eq!((at(72), at(167)), (Some(2), Some(2)));
    assert_eq!(at(168), None); // abandoned long ago: not chased
}

#[tokio::test]
async fn each_owner_is_reminded_once_at_24_hours_and_once_more_at_72() {
    let (store, mail) = (MemStore::default(), Arc::new(CaptureMailer::default()));
    let (org, c) = world(&store, "o@example.com", "Acme").await;
    add(&store, org, "p@example.com", Role::Owner).await;
    add(&store, org, "m@example.com", Role::Member).await;
    let mut sent = vec![];
    for h in [23, 25, 26, 49, 73, 74, 97, 169] {
        night(&store, &mail, c.created_at + Duration::hours(h)).await;
        sent.push(mail.sent().len());
    }
    // Re-runs and later nights send nothing more; the member is never mailed.
    assert_eq!(sent, [0, 2, 2, 2, 4, 4, 4, 4]);
    let m = mail.sent();
    let to: Vec<_> = m.iter().map(|m| m.to.as_str()).collect();
    let owners = ["o@example.com", "p@example.com"];
    assert_eq!(to, [owners, owners].concat());
    let link = format!("https://opsagent.test/o/acme/connections/{}", c.id);
    assert_eq!(
        m[0].subject,
        "Your OpsAgent cloud connection is not finished"
    );
    assert_eq!(
        m[0].text,
        format!(
            "The connection \"Prod\" is not finished, so OpsAgent is not scanning that account \
             yet.\n\nNext step: create the read-only role in your cloud account with the link \
             on the connection's page, then press Verify connection.\n\nOpen the connection: \
             {link}"
        )
    );
    assert_eq!(
        m[2].subject,
        "Last reminder: Your OpsAgent cloud connection is not finished"
    );
    assert!(m[2].text.starts_with(
        "The connection \"Prod\" is not finished, so OpsAgent is not scanning that account \
         yet. This is the last reminder.\n\nNext step: create"
    ));
    let html = m[0].html.as_deref().unwrap();
    assert!(html.contains(&format!("href=\"{link}\"")) && html.contains("Open connection"));
    assert!(!html.contains("nsubscribe"));
    let keys: std::collections::HashSet<_> = m.iter().map(|m| &m.idempotency_key).collect();
    assert_eq!(keys.len(), 4);
}

#[tokio::test]
async fn several_due_connections_are_one_mail_to_each_owner() {
    let (store, mail) = (MemStore::default(), Arc::new(CaptureMailer::default()));
    let (org, c) = world(&store, "o@example.com", "Acme").await;
    add(&store, org, "p@example.com", Role::Owner).await;
    named(&store, org, "Staging").await;
    named(&store, org, "Dev").await;
    let mut sent = vec![];
    for h in [25, 26, 73, 74] {
        night(&store, &mail, c.created_at + Duration::hours(h)).await;
        sent.push(mail.sent().len());
    }
    // Three connections, two owners: one mail each per step, never one per connection.
    assert_eq!(sent, [2, 2, 4, 4]);
    let m = mail.sent();
    assert_eq!(
        (m[0].to.as_str(), m[1].to.as_str()),
        ("o@example.com", "p@example.com")
    );
    assert_eq!(
        m[0].subject,
        "Your OpsAgent cloud connections are not finished"
    );
    assert_eq!(
        m[0].text,
        "These connections are not finished, so OpsAgent is not scanning those accounts yet: \
         \"Prod\", \"Staging\", \"Dev\".\n\nNext step for each: open it, create the read-only \
         role in your cloud account with the link on its page, then press Verify \
         connection.\n\nOpen your connections: https://opsagent.test/o/acme/connections"
    );
    let html = m[0].html.as_deref().unwrap();
    assert!(html.contains("href=\"https://opsagent.test/o/acme/connections\""));
    assert!(html.contains("Open connections"));
    assert_eq!(
        m[2].subject,
        "Last reminder: Your OpsAgent cloud connections are not finished"
    );
    assert!(m[2]
        .text
        .contains("\"Dev\". This is the last reminder.\n\n"));
}

#[test]
fn a_list_names_five_and_is_the_last_only_when_it_is_for_all() {
    let names = ["A", "B", "C", "D", "E", "F", "G"];
    let mut all: Vec<Due> = names.iter().map(|n| due(Some(n), 2, None)).collect();
    let m = mail_for(&all);
    assert!(m.subject.starts_with("Last reminder: "));
    assert!(m.text.contains(
        "yet: \"A\", \"B\", \"C\", \"D\", \"E\" and 2 more. This is the last reminder.\n\n"
    ));
    assert!(!m.text.contains("refused"));
    // One still at its first reminder, one refused, one without a name.
    all[6] = due(None, 1, Some(REFUSED));
    let m = mail_for(&all[4..]);
    assert_eq!(
        m.subject,
        "Your OpsAgent cloud connections are not finished"
    );
    assert!(m
        .text
        .contains("yet: \"E\", \"F\", an unnamed connection.\n\n"));
    assert!(m.text.contains(
        "Verify connection. Where OpsAgent already tried and your cloud provider refused \
         access, check the role first.\n\n"
    ));
}

#[tokio::test]
async fn a_night_sends_at_most_thirty_and_the_rest_wait() {
    let (store, mail) = (MemStore::default(), Arc::new(CaptureMailer::default()));
    let mut first = None;
    for i in 0..MAILS_A_NIGHT + 1 {
        let (_, c) = world(&store, &format!("o{i}@example.com"), &format!("Org {i}")).await;
        first.get_or_insert(c.created_at);
    }
    let now = Utc::now() + Duration::hours(25);
    let st = sync(&store, &mail, now).nightly(Uuid::new_v4(), now).await;
    let st = st.unwrap();
    assert_eq!(
        (&st["failed"], &st["connection_reminders"]),
        (&0.into(), &30.into())
    );
    assert_eq!(mail.sent().len(), 30);
    // The next night: only the one left out.
    night(&store, &mail, now + Duration::hours(24)).await;
    let to: std::collections::HashSet<_> = mail.sent().into_iter().map(|m| m.to).collect();
    assert_eq!((mail.sent().len(), to.len()), (31, 31));
}

#[tokio::test]
async fn one_owner_whose_mail_fails_does_not_stop_the_others() {
    let (store, mail) = (MemStore::default(), Arc::new(CaptureMailer::default()));
    let (org, c) = world(&store, "o@example.com", "Acme").await;
    add(&store, org, "p@example.com", Role::Owner).await;
    add(&store, org, "q@example.com", Role::Owner).await;
    let now = c.created_at + Duration::hours(25);
    let down = sync_with(
        &store,
        Arc::new(DownFor("p@example.com", mail.clone())),
        now,
    );
    let st = down.nightly(Uuid::new_v4(), now).await.unwrap();
    // The pass is counted as failed, and the owners before and after still got theirs.
    assert_eq!(st["failed"], 1, "{st}");
    let to = |m: Vec<Mail>| m.into_iter().map(|m| m.to).collect::<Vec<_>>();
    assert_eq!(to(mail.sent()), ["o@example.com", "q@example.com"]);
    // The next pass sends only the one that failed.
    for h in [1, 2] {
        night(&store, &mail, now + Duration::hours(h)).await;
    }
    assert_eq!(to(mail.sent())[2..], ["p@example.com"]);
}

#[tokio::test]
async fn only_a_pending_connection_of_a_live_organisation_is_reminded() {
    let (store, mail) = (MemStore::default(), Arc::new(CaptureMailer::default()));
    let (org, c) = world(&store, "o@example.com", "Acme").await;
    // Finished, being verified, and removed.
    let repo = store.connections();
    assert!(repo
        .cas_status(org, c.id, S::Pending, S::Verifying, None)
        .await
        .unwrap());
    connected(&store, org).await;
    let removed = pending(&store, org).await;
    assert!(repo
        .cas_status(org, removed.id, S::Pending, S::Disconnected, None)
        .await
        .unwrap());
    // An organisation waiting to be purged.
    let (gone, _) = world(&store, "g@example.com", "Gone").await;
    store.soft_delete(gone, c.created_at).await.unwrap();
    for h in [25, 73] {
        night(&store, &mail, Utc::now() + Duration::hours(h)).await;
    }
    assert!(mail.sent().is_empty());
}

#[tokio::test]
async fn a_read_only_organisation_is_not_reminded() {
    let (store, mail) = (MemStore::default(), Arc::new(CaptureMailer::default()));
    let (org, c) = world(&store, "o@example.com", "Acme").await;
    let paused = sub(B::Paused, c.created_at + Duration::days(20));
    store
        .apply_subscription(org, &paused, c.created_at + Duration::hours(1))
        .await
        .unwrap();
    let now = c.created_at + Duration::hours(25);
    let mut enforced = sync(&store, &mail, now);
    enforced.settings.enforced = true;
    let st = enforced.nightly(Uuid::new_v4(), now).await.unwrap();
    assert_eq!(st["failed"], 0, "{st}");
    assert_eq!(st["connection_reminders"], 0);
    // Only the paused notice went out.
    let subjects: Vec<_> = mail.sent().into_iter().map(|m| m.subject).collect();
    assert_eq!(subjects, ["OpsAgent is paused: payment overdue"]);
}

#[tokio::test]
async fn a_refused_first_connect_says_so() {
    let (store, mail) = (MemStore::default(), Arc::new(CaptureMailer::default()));
    let (org, c) = world(&store, "o@example.com", "Acme").await;
    let repo = store.connections();
    for (from, to, reason) in [
        (S::Pending, S::Verifying, None),
        (S::Verifying, S::Pending, Some(REFUSED)),
    ] {
        assert!(repo.cas_status(org, c.id, from, to, reason).await.unwrap());
    }
    for h in [25, 73] {
        night(&store, &mail, c.created_at + Duration::hours(h)).await;
    }
    let m = mail.sent();
    assert_eq!(m.len(), 2);
    assert_eq!(
        m[0].subject,
        "OpsAgent could not verify your cloud connection"
    );
    assert_eq!(
        m[0].text,
        format!(
            "The connection \"Prod\" is not finished: OpsAgent tried to verify it and your \
             cloud provider refused access, so OpsAgent is not scanning that account \
             yet.\n\nNext step: check the role. It must be the read-only role created with \
             the link on the connection's page, in the account you want to connect. Then \
             press Verify connection.\n\nOpen the connection: \
             https://opsagent.test/o/acme/connections/{}",
            c.id
        )
    );
    assert_eq!(
        m[1].subject,
        "Last reminder: OpsAgent could not verify your cloud connection"
    );
    assert!(m[1]
        .text
        .contains("account yet. This is the last reminder.\n\n"));
}

/// Kill and resume: a pass that dies at the mail marks nothing sent, and the next one sends
/// each mail once.
#[tokio::test]
async fn a_failed_pass_is_retried_and_sends_once() {
    let (store, mail) = (MemStore::default(), Arc::new(CaptureMailer::default()));
    let (_, c) = world(&store, "o@example.com", "Acme").await;
    let now = c.created_at + Duration::hours(25);
    let down = sync_with(&store, Arc::new(FailingMailer), now);
    let st = down.nightly(Uuid::new_v4(), now).await.unwrap();
    assert_eq!(st["failed"], 1, "{st}");
    for _ in 0..2 {
        night(&store, &mail, now).await;
    }
    assert_eq!(mail.sent().len(), 1);
}

/// A name cannot put a link in the mail.
#[test]
fn the_name_is_mail_safe() {
    let m = mail_for(&[due(Some("evil.example/x"), 1, None)]);
    assert!(m
        .text
        .starts_with("The connection \"evil[.]example x\" is not finished"));
    let m = mail_for(&[due(None, 1, None)]);
    assert!(m.text.starts_with("Your cloud connection is not finished"));
}
