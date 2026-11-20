//! Reminders for cloud connections left `pending` (PRD 7.2, "Customer never clicks done"): a
//! connection is due one once it is 24 hours old and a last one once it is 72 hours old, on the
//! first nightly pass after each mark. An owner gets at most one mail a night for the
//! organisation, covering every connection due. Each connection's step is one ledger effect
//! per owner (`connection:reminder:<connection>:<step>:<owner>`) on the marker run at the
//! connection's creation, begun before the mail and done after it, so a re-run or a resumed
//! pass sends nothing twice and no connection gets more than two.
use chrono::{DateTime, Duration, Utc};
use opsagent_core::{
    connection::{Connection, ConnectionStatus as S},
    org::org_web_base,
};
use opsagent_deliver::route::Recipient;
use opsagent_ledger::{EffectState, LedgerError};
use uuid::Uuid;

use crate::{
    actions::{
        billing::BillingSync,
        runs::{
            classify::{lerr, LResult},
            notice_marker,
        },
    },
    mailers::{branded, magic_link::mail_safe_name, Mail},
};

const FIRST_AFTER_HOURS: i64 = 24;
const LAST_AFTER_HOURS: i64 = 72;
/// An older pending connection gets nothing: the PRD keeps one 7 days, and connections
/// abandoned before these mails existed are not chased on deploy.
const STOP_AFTER_HOURS: i64 = 7 * 24;
/// `status_reason` of a pending connection whose first verify the cloud refused.
const REFUSED: &str = "access_denied";
/// Reminder mails one nightly pass may try, across all organisations; the rest wait for the
/// next night (or are dropped once past their window).
/// shortcut: a fixed share of the Resend free plan's 100 mails a day, which sign-in codes
/// also need; make it a share of the day's remaining count if the plan or the volume changes.
pub(super) const MAILS_A_NIGHT: u64 = 30;
/// Connections named in one mail; the rest are "and N more".
const NAMED: usize = 5;

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

/// A pending connection, the reminder it is due, and the marker run that records it.
struct Due {
    c: Connection,
    step: u8,
    marker: Uuid,
}

impl Due {
    fn refused(&self) -> bool {
        self.c.status_reason.as_deref() == Some(REFUSED)
    }

    /// The mail-safe display name in quotes, when there is one.
    fn name(&self) -> Option<String> {
        let name = self.c.display_name.as_deref().map(mail_safe_name);
        name.filter(|n| !n.is_empty()).map(|n| format!("\"{n}\""))
    }
}

/// One owner's mail; `open` is the text line before `link`, `label` its button.
struct Reminder {
    subject: String,
    lead: String,
    next: String,
    open: &'static str,
    label: &'static str,
    link: String,
}

impl Reminder {
    /// About the one connection `d`, linking to its page.
    fn one(d: &Due, base: &str) -> Self {
        let name = d.name().map(|n| format!("The connection {n}"));
        let name = name.unwrap_or_else(|| "Your cloud connection".into());
        let (subject, lead, next) = if d.refused() {
            (
                "OpsAgent could not verify your cloud connection",
                format!(
                    "{name} is not finished: OpsAgent tried to verify it and your cloud \
                     provider refused access, so OpsAgent is not scanning that account yet."
                ),
                "Next step: check the role. It must be the read-only role created with the \
                 link on the connection's page, in the account you want to connect. Then press \
                 Verify connection.",
            )
        } else {
            (
                "Your OpsAgent cloud connection is not finished",
                format!("{name} is not finished, so OpsAgent is not scanning that account yet."),
                "Next step: create the read-only role in your cloud account with the link on \
                 the connection's page, then press Verify connection.",
            )
        };
        Self {
            subject: subject.into(),
            lead,
            next: next.into(),
            open: "Open the connection",
            label: "Open connection",
            link: format!("{base}/connections/{}", d.c.id),
        }
    }

    /// Listing `due` (the first `NAMED` by name), linking to the connections list.
    fn several(due: &[&Due], base: &str) -> Self {
        let named = due.iter().take(NAMED);
        let names: Vec<_> = named
            .map(|d| d.name().unwrap_or_else(|| "an unnamed connection".into()))
            .collect();
        let mut names = names.join(", ");
        if due.len() > NAMED {
            names += &format!(" and {} more", due.len() - NAMED);
        }
        let mut next = "Next step for each: open it, create the read-only role in your cloud \
                        account with the link on its page, then press Verify connection."
            .to_owned();
        if due.iter().any(|d| d.refused()) {
            next += " Where OpsAgent already tried and your cloud provider refused access, \
                     check the role first.";
        }
        Self {
            subject: "Your OpsAgent cloud connections are not finished".into(),
            lead: format!(
                "These connections are not finished, so OpsAgent is not scanning those \
                 accounts yet: {names}."
            ),
            next,
            open: "Open your connections",
            label: "Open connections",
            link: format!("{base}/connections"),
        }
    }

    /// The mail for `due` (never empty) to `to`. "Last reminder" only when it is the last for
    /// every connection in it.
    fn mail(due: &[&Due], base: &str, to: String) -> Mail {
        let r = match due {
            [d] => Self::one(d, base),
            _ => Self::several(due, base),
        };
        let (subject, last) = match due.iter().all(|d| d.step > 1) {
            true => (
                format!("Last reminder: {}", r.subject),
                " This is the last reminder.",
            ),
            false => (r.subject, ""),
        };
        let text = format!("{}{last}\n\n{}\n\n{}: {}", r.lead, r.next, r.open, r.link);
        Mail {
            to,
            html: Some(branded(&subject, &text, Some((r.label, &r.link)))),
            subject,
            text,
            ..Default::default()
        }
    }
}

impl BillingSync {
    /// Mails each owner of `org` one reminder for its pending connections due one `now`, while
    /// `mails` (the pass's count of reminder mails tried) is under `MAILS_A_NIGHT`. A failed
    /// send does not stop the other owners; it fails the organisation's pass, and the next
    /// night sends what is still owed.
    pub(super) async fn connection_reminders(
        &self,
        org: Uuid,
        now: DateTime<Utc>,
        mails: &mut u64,
    ) -> LResult<()> {
        if *mails >= MAILS_A_NIGHT {
            return Ok(());
        }
        let due = self.due_reminders(org, now).await?;
        if due.is_empty() {
            return Ok(());
        }
        let o = self.uow.orgs().get(org).await.map_err(lerr)?;
        let slug = o.ok_or(LedgerError::NotFound)?.slug;
        let base = org_web_base(&self.settings.web_base_url, &slug);
        // One a night for an owner: a retry the same day is the same mail to Resend.
        let night = format!("connection:reminders:{org}:{}", now.date_naive());
        let mut failed = false;
        for o in self.uow.recipients().owners(org).await.map_err(lerr)? {
            if *mails >= MAILS_A_NIGHT {
                break;
            }
            let sent = self.remind_owner(org, o, &due, (&base, &night), mails);
            failed |= !sent.await?;
        }
        match failed {
            true => Err(LedgerError::Job {
                code: "mail_failed".into(),
                retry: true,
            }),
            false => Ok(()),
        }
    }

    /// The pending connections of `org` in a reminder window `now`, oldest first.
    async fn due_reminders(&self, org: Uuid, now: DateTime<Utc>) -> LResult<Vec<Due>> {
        let mut due = vec![];
        for c in self.uow.connections().list(org).await.map_err(lerr)? {
            let step = step(now - c.created_at).filter(|_| c.status == S::Pending);
            if let Some(step) = step {
                let marker = notice_marker(&*self.uow, Some(org), c.created_at).await?;
                due.push(Due { c, step, marker });
            }
        }
        Ok(due)
    }

    /// One mail to `o` for the connections in `due` it has not been reminded of at that step:
    /// each effect is begun before the mail and done after it. `false` when the send failed
    /// (the effects stay begun, so the next pass sends again).
    async fn remind_owner(
        &self,
        org: Uuid,
        o: Recipient,
        due: &[Due],
        (base, night): (&str, &str),
        mails: &mut u64,
    ) -> LResult<bool> {
        let guard = &self.guard;
        if !guard
            .may_deliver(org, &o.email, o.member)
            .await
            .map_err(lerr)?
        {
            return Ok(true);
        }
        let ledger = self.uow.ledger();
        let mut owed = vec![];
        for d in due {
            let key = format!("connection:reminder:{}:{}:{}", d.c.id, d.step, o.id);
            if !matches!(
                ledger.effect_begin(d.marker, &key).await?,
                EffectState::Done(_)
            ) {
                owed.push((d, key));
            }
        }
        if owed.is_empty() {
            return Ok(true);
        }
        *mails += 1;
        let about: Vec<&Due> = owed.iter().map(|(d, _)| *d).collect();
        let mail = Mail {
            idempotency_key: Some(format!("{night}:{}", o.id)),
            ..Reminder::mail(&about, base, o.email)
        };
        if self.mailer.send(mail).await.is_err() {
            tracing::warn!(
                error_code = "mail_failed",
                "connection reminder mail failed"
            );
            return Ok(false);
        }
        for (d, key) in owed {
            ledger.effect_done(d.marker, &key, None).await?;
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests;
