//! The mails after a delete: "organisation deleted" to every owner, "account deleted" to the
//! address the account had. The addresses are read before the delete and the mails go out
//! after it commits. Each mail is one ledger effect on a marker run, so it is sent once; a
//! failure is logged and never reaches the caller, so it cannot block or undo the delete.
use chrono::{DateTime, Utc};
use opsagent_ledger::{effects::with_effect, LedgerError};
use uuid::Uuid;

use crate::{
    actions::{runs::notice_marker, uow::UnitOfWork},
    mailers::{branded, Mail, Mailer},
};

/// The "organisation deleted" mail to `to`. `name` and `by` are already mail-safe.
pub fn org_deleted(to: String, name: &str, by: &str, had_subscription: bool) -> Mail {
    let subscription = if had_subscription {
        " Its subscription is cancelled and nothing more is charged."
    } else {
        ""
    };
    let text = format!(
        "The organisation {name} was deleted by {by}.\n\nIts cloud connections, findings and \
         settings are removed.{subscription}"
    );
    notice(
        to,
        format!("The OpsAgent organisation {name} was deleted"),
        text,
    )
}

/// The "account deleted" mail to `to`, the address the account had.
pub fn account_deleted(to: String) -> Mail {
    let text = "Your OpsAgent account and its sign-in methods are removed.\n\nYou can sign up \
                again at any time.";
    notice(to, "Your OpsAgent account was deleted".into(), text.into())
}

fn notice(to: String, subject: String, text: String) -> Mail {
    Mail {
        to,
        html: Some(branded(&subject, &text, None)),
        subject,
        text,
        ..Default::default()
    }
}

/// Sends each `(ledger key, mail)` once, on the marker run of `org` at `anchor`.
pub async fn send_once(
    uow: &dyn UnitOfWork,
    mailer: &dyn Mailer,
    org: Option<Uuid>,
    anchor: DateTime<Utc>,
    mails: Vec<(String, Mail)>,
) {
    let failed = || tracing::warn!(error_code = "mail_failed", "deleted notice mail failed");
    let Ok(marker) = notice_marker(uow, org, anchor).await else {
        return failed();
    };
    for (key, mail) in mails {
        let mail = Mail {
            idempotency_key: Some(format!("{marker}:{key}")),
            ..mail
        };
        let sent = with_effect(uow.ledger(), marker, &key, true, || async {
            let sent = mailer.send(mail).await;
            sent.map(|()| None).map_err(|_| LedgerError::Job {
                code: "mail_failed".into(),
                retry: false,
            })
        })
        .await;
        if sent.is_err() {
            failed();
        }
    }
}
