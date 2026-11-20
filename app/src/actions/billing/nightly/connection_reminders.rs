//! Reminders for a cloud connection left `pending` (PRD 7.2, "Customer never clicks done"):
//! the owners get one mail once it is 24 hours old and a last one once it is 72 hours old, on
//! the first nightly pass after each mark. Each mail is one ledger effect
//! (`connection:reminder:<connection>:<step>:<owner>`) on the marker run at the connection's
//! creation, so a re-run or a resumed pass sends nothing twice.
use chrono::{DateTime, Duration, Utc};
use opsagent_core::{
    connection::{Connection, ConnectionStatus as S},
    org::org_web_base,
};
use opsagent_ledger::LedgerError;
use uuid::Uuid;

use crate::{
    actions::{
        billing::BillingSync,
        runs::classify::{lerr, LResult},
    },
    mailers::magic_link::mail_safe_name,
};

const FIRST_AFTER_HOURS: i64 = 24;
const LAST_AFTER_HOURS: i64 = 72;
/// An older pending connection gets nothing: the PRD keeps one 7 days, and connections
/// abandoned before these mails existed are not chased on deploy.
const STOP_AFTER_HOURS: i64 = 7 * 24;
/// `status_reason` of a pending connection whose first verify the cloud refused.
const REFUSED: &str = "access_denied";

/// The reminder due for a connection pending for `age`: 1, then 2 (the last). A first one
/// that was missed is not caught up once the last is due, so there are never more than two.
fn step(age: Duration) -> Option<u8> {
    match age.num_hours() {
        h if h < FIRST_AFTER_HOURS => None,
        h if h < LAST_AFTER_HOURS => Some(1),
        h if h < STOP_AFTER_HOURS => Some(2),
        _ => None,
    }
}

/// `(subject, text)` of reminder `step` for `c`, whose page is `link`.
fn mail(c: &Connection, step: u8, link: &str) -> (String, String) {
    let name = c.display_name.as_deref().map(mail_safe_name);
    let name = match name.filter(|n| !n.is_empty()) {
        Some(n) => format!("The connection \"{n}\""),
        None => "Your cloud connection".into(),
    };
    let (subject, lead, next) = if c.status_reason.as_deref() == Some(REFUSED) {
        (
            "OpsAgent could not verify your cloud connection",
            format!(
                "{name} is not finished: OpsAgent tried to verify it and your cloud provider \
                 refused access, so OpsAgent is not scanning that account yet."
            ),
            "Next step: check the role. It must be the read-only role created with the link \
             OpsAgent gave you, in the account you want to connect. Then press Verify \
             connection.",
        )
    } else {
        (
            "Your OpsAgent cloud connection is not finished",
            format!("{name} is not finished, so OpsAgent is not scanning that account yet."),
            "Next step: create the read-only role in your cloud account with the link OpsAgent \
             gave you, then press Verify connection.",
        )
    };
    let (subject, last) = match step {
        1 => (subject.to_owned(), ""),
        _ => (
            format!("Last reminder: {subject}"),
            " This is the last reminder.",
        ),
    };
    let text = format!("{lead}{last}\n\n{next}\n\nOpen the connection: {link}");
    (subject, text)
}

impl BillingSync {
    /// Mails the owners of `org` the reminder due `now` for each of its pending connections;
    /// returns how many reminders this call sent.
    pub(super) async fn connection_reminders(&self, org: Uuid, now: DateTime<Utc>) -> LResult<u64> {
        let all = self.uow.connections().list(org).await.map_err(lerr)?;
        let due = all
            .iter()
            .filter(|c| c.status == S::Pending)
            .filter_map(|c| Some((c, step(now - c.created_at)?)));
        let mut sent = 0;
        for (c, step) in due {
            let o = self.uow.orgs().get(org).await.map_err(lerr)?;
            let slug = o.ok_or(LedgerError::NotFound)?.slug;
            let base = org_web_base(&self.settings.web_base_url, &slug);
            let link = format!("{base}/connections/{}", c.id);
            let (subject, text) = mail(c, step, &link);
            let key = format!("connection:reminder:{}:{step}", c.id);
            let button = ("Open connection", link.as_str());
            let mailed = self.mail_owners(org, c.created_at, &key, &subject, &text, button);
            sent += u64::from(mailed.await?);
        }
        Ok(sent)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use opsagent_core::{
        billing::{BillingRepo, BillingStatus as B},
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
        mailers::{CaptureMailer, FailingMailer},
    };

    /// An organisation "Acme" with an active subscription and one pending connection "Prod".
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
        for (email, role) in [
            ("p@example.com", Role::Owner),
            ("m@example.com", Role::Member),
        ] {
            let u = user(&store, email).await;
            store.add_member(org, u.id, role).await.unwrap();
        }
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
                "The connection \"Prod\" is not finished, so OpsAgent is not scanning that \
                 account yet.\n\nNext step: create the read-only role in your cloud account \
                 with the link OpsAgent gave you, then press Verify connection.\n\nOpen the \
                 connection: {link}"
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
                 the link OpsAgent gave you, in the account you want to connect. Then press \
                 Verify connection.\n\nOpen the connection: \
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

    /// Kill and resume: a pass that dies at the mail marks nothing sent, and the next one
    /// sends each mail once.
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
        let c = Connection {
            display_name: Some("evil.example/x".into()),
            ..blank()
        };
        let (_, text) = mail(&c, 1, "https://opsagent.test/o/acme/connections/1");
        assert!(text.starts_with("The connection \"evil[.]example x\" is not finished"));
        let unnamed = Connection {
            display_name: None,
            ..blank()
        };
        let (_, text) = mail(&unnamed, 1, "l");
        assert!(text.starts_with("Your cloud connection is not finished"));
    }

    fn blank() -> Connection {
        Connection {
            id: Uuid::nil(),
            organisation_id: Uuid::nil(),
            provider: "aws".into(),
            display_name: None,
            status: S::Pending,
            status_reason: None,
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
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}
