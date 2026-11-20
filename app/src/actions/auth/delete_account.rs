use std::sync::Arc;

use axum::http::StatusCode;
use opsagent_core::{audit::AuditEntry, org::Role, repo::Clock};
use uuid::Uuid;

use crate::{
    actions::{
        deleted_notice::{account_deleted, send_once},
        uow::UnitOfWork,
    },
    error::{AppError, AppResult},
    mailers::Mailer,
};

/// Deletes the signed-in user's account (PRD: refused while they are the only owner of an
/// organisation). Leaves every organisation the way member removal does, then erases the user,
/// in one transaction. The caller flushes the session; other sessions die on their next request
/// because the user no longer resolves. Afterwards the address the account had is mailed
/// once (`deleted_notice`); a mail failure changes nothing.
pub struct DeleteAccount {
    uow: Arc<dyn UnitOfWork>,
    clock: Arc<dyn Clock>,
    mailer: Arc<dyn Mailer>,
}

impl DeleteAccount {
    pub fn new(uow: Arc<dyn UnitOfWork>, clock: Arc<dyn Clock>, mailer: Arc<dyn Mailer>) -> Self {
        Self { uow, clock, mailer }
    }

    /// `confirm` must be the account's email (any case).
    pub async fn run(&self, user_id: Uuid, confirm: &str) -> AppResult<()> {
        let user = self
            .uow
            .users()
            .get(user_id)
            .await?
            .ok_or(AppError::Unauthenticated)?;
        if !confirm.trim().eq_ignore_ascii_case(user.email.as_str()) {
            return Err(AppError::Refused {
                status: StatusCode::UNPROCESSABLE_ENTITY,
                code: "confirm_mismatch",
                detail: "Type your email address exactly to confirm.".into(),
            });
        }
        let tx = self.uow.begin().await?;
        let mut orgs = tx.orgs().list_for_user(user_id).await?;
        // A fixed lock order, so two concurrent deletions cannot deadlock.
        orgs.sort_by_key(|(o, _)| o.id);
        for (o, _) in &orgs {
            tx.orgs().lock(o.id).await?;
        }
        let mut sole = Vec::new();
        for (o, role) in &orgs {
            if *role == Role::Owner && tx.orgs().owner_count(o.id).await? <= 1 {
                sole.push(o.name.clone());
            }
        }
        if !sole.is_empty() {
            return Err(AppError::Refused {
                status: StatusCode::CONFLICT,
                code: "last_owner",
                detail: format!(
                    "You are the only owner of {}. Make someone else an owner, or delete the organisation, first.",
                    sole.join(", ")
                ),
            });
        }
        let now = self.clock.now();
        for (o, _) in &orgs {
            let members = tx.orgs().members(o.id).await?;
            let Some(m) = members.into_iter().find(|m| m.user_id == user_id) else {
                continue;
            };
            // Same effects as RemoveMember: membership (and with it chat history) gone,
            // pending invites to them cancelled, their grants revoked.
            tx.orgs().remove_member(o.id, m.id).await?;
            tx.oauth().revoke_member_grants(o.id, m.id, now).await?;
            let target = Some(("member", m.id.to_string()));
            let entry = AuditEntry::member(Some(o.id), user_id, "member.remove", target);
            tx.audit().record(entry).await?;
        }
        tx.users().erase(user_id, now).await?;
        // Their account-level trail (sign-ins, passkeys, name, consents) goes with them; one
        // record that names nobody stays (retention removes it after a year).
        tx.retention().erase_account_audit(user_id, now).await?;
        tx.commit().await?;
        // To the address read before the erase.
        let mail = account_deleted(user.email.as_str().to_owned());
        let mails = vec![(format!("account_deleted:{user_id}"), mail)];
        send_once(&*self.uow, &*self.mailer, None, user.created_at, mails).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use opsagent_core::{org::OrganisationsRepo, repo::SystemClock, user::UsersRepo};

    use super::*;
    use crate::{
        actions::orgs::test_support::*,
        adapters::memory::MemStore,
        mailers::{CaptureMailer, FailingMailer},
    };

    fn action(store: &MemStore) -> DeleteAccount {
        action_with(store, Arc::new(CaptureMailer::default()))
    }

    fn action_with(store: &MemStore, mailer: Arc<dyn Mailer>) -> DeleteAccount {
        DeleteAccount::new(Arc::new(store.clone()), Arc::new(SystemClock), mailer)
    }

    #[tokio::test]
    async fn the_address_the_account_had_is_mailed_once() {
        let store = MemStore::default();
        let u = user(&store, "pat@example.com").await;
        // A refused delete mails nobody.
        let sent = Arc::new(CaptureMailer::default());
        let delete = action_with(&store, sent.clone());
        assert!(delete.run(u.id, "pat@").await.is_err());
        assert!(sent.sent().is_empty());
        delete.run(u.id, "pat@example.com").await.unwrap();
        // The account is gone, so a second delete is refused and mails nobody.
        assert!(delete.run(u.id, "pat@example.com").await.is_err());
        let m = sent.sent();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].to, "pat@example.com");
        assert_eq!(m[0].subject, "Your OpsAgent account was deleted");
        assert_eq!(
            m[0].text,
            "Your OpsAgent account and its sign-in methods are removed.\n\nYou can sign up \
             again at any time."
        );
        let html = m[0].html.as_deref().unwrap();
        assert!(
            html.contains("OpsAgent") && !html.contains("href=\"http"),
            "{html}"
        );
        // The ledger key is spent: the same mail offered again is not sent.
        let again = vec![(format!("account_deleted:{}", u.id), m[0].clone())];
        send_once(&store, &*sent, None, u.created_at, again).await;
        assert_eq!(sent.sent().len(), 1);
    }

    #[tokio::test]
    async fn a_failing_mailer_does_not_fail_the_delete() {
        let store = MemStore::default();
        let u = user(&store, "pat@example.com").await;
        let delete = action_with(&store, Arc::new(FailingMailer));
        delete.run(u.id, "pat@example.com").await.unwrap();
        assert!(UsersRepo::get(&store, u.id).await.unwrap().is_none());
    }

    fn refused(err: AppError) -> (StatusCode, &'static str, String) {
        let AppError::Refused {
            status,
            code,
            detail,
        } = err
        else {
            panic!("{err:?}")
        };
        (status, code, detail)
    }

    #[tokio::test]
    async fn the_email_must_be_typed_to_confirm() {
        let store = MemStore::default();
        let u = user(&store, "pat@example.com").await;
        let (status, code, _) = refused(action(&store).run(u.id, "pat@").await.unwrap_err());
        assert_eq!(
            (status, code),
            (StatusCode::UNPROCESSABLE_ENTITY, "confirm_mismatch")
        );
        assert!(UsersRepo::get(&store, u.id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn the_only_owner_is_refused_and_told_which_organisation() {
        let store = MemStore::default();
        let (owner, org) = owned_org(&store, "only@example.com", "Solo").await;
        let (status, code, detail) = refused(
            action(&store)
                .run(owner.id, "ONLY@example.com")
                .await
                .unwrap_err(),
        );
        assert_eq!((status, code), (StatusCode::CONFLICT, "last_owner"));
        assert!(detail.contains("Solo"), "{detail}");
        assert_eq!(store.members(org.id).await.unwrap().len(), 1);
        assert!(UsersRepo::get(&store, owner.id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn a_member_is_removed_everywhere_and_the_account_is_erased() {
        let store = MemStore::default();
        let (owner, org) = owned_org(&store, "boss@example.com", "Acme").await;
        let pat = user(&store, "pat@example.com").await;
        store
            .add_member(org.id, pat.id, Role::Member)
            .await
            .unwrap();
        // Pat co-owns a second organisation with someone else, so leaving it is allowed.
        let (other_owner, org2) = owned_org(&store, "sam@example.com", "Beta").await;
        store
            .add_member(org2.id, pat.id, Role::Owner)
            .await
            .unwrap();

        action(&store)
            .run(pat.id, " pat@example.com ")
            .await
            .unwrap();

        assert!(UsersRepo::get(&store, pat.id).await.unwrap().is_none());
        let email = opsagent_core::user::Email::parse("pat@example.com").unwrap();
        assert!(store.find_by_email(&email).await.unwrap().is_none());
        for (o, left) in [(org.id, owner.id), (org2.id, other_owner.id)] {
            let ids: Vec<_> = store
                .members(o)
                .await
                .unwrap()
                .into_iter()
                .map(|m| m.user_id)
                .collect();
            assert_eq!(ids, [left]);
        }
        let actions: Vec<_> = store
            .audit_entries()
            .into_iter()
            .map(|e| e.action)
            .collect();
        assert_eq!(actions.iter().filter(|a| *a == "member.remove").count(), 2);
        assert!(actions.iter().any(|a| a == "user.delete"));
    }

    #[tokio::test]
    async fn account_level_audit_entries_are_erased_with_the_account() {
        use opsagent_core::audit::{Actor, AuditLog};
        let store = MemStore::default();
        let pat = user(&store, "pat@example.com").await;
        let sam = user(&store, "sam@example.com").await;
        let about = Some(("user", pat.id.to_string()));
        for (who, action, target) in [
            (pat.id, "auth.sign_in", about.clone()),
            (pat.id, "auth.passkey_added", Some(("passkey", "p".into()))),
            (pat.id, "user.update_name", about),
            (sam.id, "auth.sign_in", Some(("user", sam.id.to_string()))),
        ] {
            let entry = AuditEntry::member(None, who, action, target);
            store.record(entry).await.unwrap();
        }

        action(&store).run(pat.id, "pat@example.com").await.unwrap();

        // Sam's entry stays; Pat's are gone but for one record that names nobody.
        let left = store.audit_entries();
        assert_eq!(left.len(), 2, "{left:?}");
        assert_eq!(left[0].actor, Actor::Member(sam.id));
        let record = &left[1];
        assert_eq!(record.action, "user.delete");
        assert_eq!((record.actor, &record.target), (Actor::System, &None));
        assert!(!format!("{record:?}").contains(&pat.id.to_string()));
    }
}
