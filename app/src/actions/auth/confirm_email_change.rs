//! The second half of changing the sign-in address: the code from the new address moves the
//! account to it. Ending the user's other sessions is the caller's (transport) job.
use std::sync::Arc;

use axum::http::StatusCode;
use opsagent_core::{
    audit::AuditEntry,
    repo::{Clock, RepoError},
    user::User,
};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use super::verify_code::{CAP, DAY_CAP, WINDOW_SECS};
use crate::{
    actions::{uow::UnitOfWork, RateLimiter, DAY_SECS},
    error::{AppError, AppResult},
    mailers::{magic_link as mail, Mailer},
    tokens::code_hash,
};

pub struct ConfirmEmailChange {
    uow: Arc<dyn UnitOfWork>,
    limiter: Arc<dyn RateLimiter>,
    mailer: Arc<dyn Mailer>,
    web_base_url: String,
    clock: Arc<dyn Clock>,
    secret: String,
}

impl ConfirmEmailChange {
    pub fn new(
        uow: Arc<dyn UnitOfWork>,
        limiter: Arc<dyn RateLimiter>,
        mailer: Arc<dyn Mailer>,
        web_base_url: String,
        clock: Arc<dyn Clock>,
        secret: String,
    ) -> Self {
        Self {
            uow,
            limiter,
            mailer,
            web_base_url,
            clock,
            secret,
        }
    }

    /// The sign-in code's attempt caps, per user: 10 per 15 minutes and 20 per day. Fails
    /// closed: a limiter error is also a 429.
    async fn within_caps(&self, user_id: Uuid) -> AppResult<()> {
        for (name, cap, window) in [("", CAP, WINDOW_SECS), ("_day", DAY_CAP, DAY_SECS)] {
            let key = format!("ratelimit:email_change_confirm{name}:user:{user_id}");
            let ok = self.limiter.hit(&key, cap, window).await;
            if !ok.unwrap_or_else(|e| {
                tracing::warn!(error = %e, "email change rate limit unavailable, refusing");
                false
            }) {
                return Err(AppError::RateLimited {
                    detail: "Too many attempts. Try again in a few minutes.".into(),
                    retry_after_secs: WINDOW_SECS as u64,
                });
            }
        }
        Ok(())
    }

    /// The user at their new address. `Gone("code_invalid")` for a wrong, spent, expired or
    /// disabled code (the fifth wrong guess disables it); 409 `email_taken` when another account
    /// took the address after the code was mailed.
    pub async fn run(&self, user_id: Uuid, code: &str) -> AppResult<User> {
        let invalid = || AppError::Gone("code_invalid");
        self.within_caps(user_id).await?;
        let code: String = code.chars().filter(char::is_ascii_digit).collect();
        if code.len() != 6 {
            return Err(invalid());
        }
        let now = self.clock.now();
        let tx = self.uow.begin().await?;
        let live = tx.users().live_email_changes(user_id, now).await?;
        // Every row is compared, so timing does not reveal which one matched.
        let mut hit = None;
        for l in &live {
            let want = code_hash(&self.secret, &l.token_hash, &code);
            if bool::from(want.as_bytes().ct_eq(l.code_hash.as_bytes())) {
                hit = Some(l);
            }
        }
        let Some(hit) = hit else {
            let ids: Vec<Uuid> = live.iter().map(|l| l.id).collect();
            tx.users().count_wrong_code(&ids).await?;
            tx.commit().await?;
            return Err(invalid());
        };
        if !tx.users().spend_code(hit.id, now).await? {
            return Err(invalid());
        }
        let user = tx.users().get(user_id).await?;
        let user = user.ok_or(AppError::Unauthenticated)?;
        // A row left by a sign-in link nobody redeemed is in the way, not an account.
        if let Some(other) = tx.users().find_by_email(&hit.new_email).await? {
            if other.id != user_id {
                tx.users().delete_unproven(other.id).await?;
            }
        }
        // The unique index decides for a proven account, and a race with one; the transaction
        // is dropped either way.
        let moved = tx.users().set_email(user_id, &hit.new_email).await;
        moved.map_err(|e| match e {
            RepoError::Conflict("email_taken") => AppError::Refused {
                status: StatusCode::CONFLICT,
                code: "email_taken",
                detail: "That address can no longer be used. Nothing was changed.".into(),
            },
            // Erased since the code was mailed: there is no account to move.
            RepoError::NotFound => AppError::Unauthenticated,
            e => e.into(),
        })?;
        // Briefings and alerts to this member follow, in every organisation.
        let recipients = tx.recipients();
        recipients
            .move_member_email(user_id, hit.new_email.as_str())
            .await?;
        let target = Some(("user", user_id.to_string()));
        let entry = AuditEntry::member(None, user_id, "auth.email_changed", target);
        tx.audit().record(entry).await?;
        tx.commit().await?;
        let notice = mail::email_changed(
            user.email.as_str(),
            hit.new_email.as_str(),
            &self.web_base_url,
        );
        if let Err(e) = self.mailer.send(notice).await {
            tracing::error!(error = %e, "email changed notice failed");
        }
        Ok(User {
            email: hit.new_email.clone(),
            ..user
        })
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use opsagent_core::{
        repo::{FixedClock, SystemClock},
        user::{Email, NewMagicLink, SignupAllowlist, UsersRepo},
    };

    use super::*;
    use crate::{
        actions::auth::{
            test_support::*, GithubProfile, GoogleProfile, RedeemMagicLink, RequestEmailChange,
            SignInGithub, SignInGoogle,
        },
        adapters::memory::{MemRateLimiter, MemStore},
        mailers::CaptureMailer,
        tokens::hash_token,
    };

    const OLD: &str = "old@example.com";
    const NEW: &str = "jane@new.example";

    struct Fixture {
        store: MemStore,
        mail: Arc<CaptureMailer>,
        user: User,
        request: RequestEmailChange,
    }

    fn email(s: &str) -> Email {
        Email::parse(s).unwrap()
    }

    async fn fixture_with(signup: SignupAllowlist) -> Fixture {
        let (store, mail) = (MemStore::default(), Arc::new(CaptureMailer::default()));
        let users: &dyn UsersRepo = &store;
        let user = users.find_or_create_by_email(&email(OLD)).await.unwrap();
        let request = RequestEmailChange::new(
            Arc::new(store.clone()),
            (Arc::new(MemRateLimiter::default()), 1000),
            mail.clone(),
            Arc::new(SystemClock),
            SECRET.into(),
            signup,
        );
        Fixture {
            store,
            mail,
            user,
            request,
        }
    }

    async fn fixture() -> Fixture {
        fixture_with(SignupAllowlist::default()).await
    }

    impl Fixture {
        fn confirm_at(&self, clock: Arc<dyn Clock>) -> ConfirmEmailChange {
            ConfirmEmailChange::new(
                Arc::new(self.store.clone()),
                Arc::new(MemRateLimiter::default()),
                self.mail.clone(),
                WEB.into(),
                clock,
                SECRET.into(),
            )
        }

        fn confirm(&self) -> ConfirmEmailChange {
            self.confirm_at(Arc::new(SystemClock))
        }

        /// Asks for `to` and returns the mailed code.
        async fn ask(&self, to: &str) -> String {
            self.request.run(self.user.id, to, None).await.unwrap();
            last_code(&self.mail)
        }

        async fn stored_email(&self) -> String {
            let users: &dyn UsersRepo = &self.store;
            let u = users.get(self.user.id).await.unwrap().unwrap();
            u.email.as_str().to_owned()
        }
    }

    fn assert_invalid<T: std::fmt::Debug>(r: AppResult<T>) {
        assert!(matches!(r, Err(AppError::Gone("code_invalid"))), "{r:?}");
    }

    fn wrong(code: &str) -> String {
        if code == "000000" { "000001" } else { "000000" }.into()
    }

    #[tokio::test]
    async fn the_code_from_the_new_address_moves_the_account_once() {
        let f = fixture().await;
        // A sign-in link mailed to the old address before the change.
        let users: &dyn UsersRepo = &f.store;
        let soon = Utc::now() + Duration::minutes(15);
        let old_link = hash_token("old-link");
        users
            .issue_magic_link(NewMagicLink::new(
                f.user.id,
                &f.user.email,
                &old_link,
                "c",
                soon,
            ))
            .await
            .unwrap();

        let code = f.ask(" Jane@New.Example ").await;
        let sent = f.mail.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].to, NEW);
        assert!(code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()));
        assert_eq!(f.stored_email().await, OLD, "nothing moves before the code");

        let confirm = f.confirm();
        let spaced = format!("{} {}", &code[..3], &code[3..]);
        let got = confirm.run(f.user.id, &spaced).await.unwrap();
        assert_eq!((got.id, got.email.as_str()), (f.user.id, NEW));
        assert_eq!(f.stored_email().await, NEW);
        assert_invalid(confirm.run(f.user.id, &code).await);

        // The old address is told, with the new one masked.
        let sent = f.mail.sent();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[1].to, OLD);
        assert_eq!(sent[1].subject, "Your OpsAgent sign-in email was changed");
        assert_eq!(
            sent[1].text,
            "Your OpsAgent sign-in email was changed to j***@new.example. If this was not you, contact us through https://web.test/contact."
        );

        // One audit row, by and about the user, carrying no address.
        let audit: Vec<_> = f
            .store
            .audit_entries()
            .into_iter()
            .filter(|e| e.action == "auth.email_changed")
            .collect();
        assert_eq!(audit.len(), 1, "{audit:?}");
        assert_eq!(
            audit[0].actor,
            opsagent_core::audit::Actor::Member(f.user.id)
        );
        assert_eq!(audit[0].target, Some(("user", f.user.id.to_string())));
        assert_eq!(audit[0].meta, serde_json::json!({}));

        // The link mailed to the old address no longer signs in.
        let redeem = RedeemMagicLink::new(Arc::new(f.store.clone()), Arc::new(SystemClock));
        let err = redeem.run("old-link").await.unwrap_err();
        assert!(matches!(err, AppError::Gone("link_invalid")), "{err:?}");
    }

    #[tokio::test]
    async fn the_fifth_wrong_code_disables_it_and_changes_nothing() {
        let f = fixture().await;
        let code = f.ask(NEW).await;
        let confirm = f.confirm();
        for _ in 0..5 {
            assert_invalid(confirm.run(f.user.id, &wrong(&code)).await);
        }
        assert_invalid(confirm.run(f.user.id, &code).await);
        assert_invalid(confirm.run(f.user.id, "12345").await);
        assert_eq!(f.stored_email().await, OLD);
        assert_eq!(f.mail.sent().len(), 1, "no notice");
        // Ten attempts in 15 minutes, then 429 whatever the code.
        for _ in 0..3 {
            assert_invalid(confirm.run(f.user.id, &code).await);
        }
        let err = confirm.run(f.user.id, &code).await.unwrap_err();
        assert!(matches!(err, AppError::RateLimited { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn an_expired_code_and_an_older_code_are_refused() {
        let f = fixture().await;
        let first = f.ask(NEW).await;
        // A second mail whose code differs from the first, so the refusal below is not luck.
        let second = loop {
            let code = f.ask(NEW).await;
            if code != first {
                break code;
            }
        };
        assert_invalid(f.confirm().run(f.user.id, &first).await);
        let late = Arc::new(FixedClock(Utc::now() + Duration::minutes(16)));
        assert_invalid(f.confirm_at(late).run(f.user.id, &second).await);
        assert_eq!(f.stored_email().await, OLD);
        // Another user cannot spend it either.
        assert_invalid(f.confirm().run(Uuid::new_v4(), &second).await);
        f.confirm().run(f.user.id, &second).await.unwrap();
    }

    #[tokio::test]
    async fn a_taken_address_answers_the_same_and_gets_no_code() {
        let f = fixture().await;
        let users: &dyn UsersRepo = &f.store;
        let taken = email("taken@example.com");
        let other = proven(&f.store, taken.as_str()).await;
        // The same answer as a free address.
        f.request
            .run(f.user.id, taken.as_str(), None)
            .await
            .unwrap();
        let sent = f.mail.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].to, taken.as_str());
        assert_eq!(sent[0].subject, "This address already signs in to OpsAgent");
        assert!(!sent[0].text.chars().any(|c| c.is_ascii_digit()), "no code");
        assert!(!sent[0].text.contains(OLD), "the asker is not named");
        let live = users.live_email_changes(f.user.id, Utc::now()).await;
        assert!(live.unwrap().is_empty());
        assert_eq!(f.stored_email().await, OLD);
        assert_eq!(users.get(other.id).await.unwrap().unwrap().email, taken);
    }

    /// A proven account at `address`: it redeemed a sign-in link.
    async fn proven(store: &MemStore, address: &str) -> User {
        let users: &dyn UsersRepo = store;
        let e = email(address);
        let u = users.find_or_create_by_email(&e).await.unwrap();
        let hash = hash_token(address);
        let soon = Utc::now() + Duration::minutes(15);
        let link = NewMagicLink::new(u.id, &e, &hash, "c", soon);
        users.issue_magic_link(link).await.unwrap();
        let spent = users.consume_magic_link(&hash, Utc::now()).await.unwrap();
        assert!(spent.is_some());
        u
    }

    #[tokio::test]
    async fn an_address_that_only_asked_for_a_sign_in_link_is_free() {
        let f = fixture().await;
        let users: &dyn UsersRepo = &f.store;
        // Somebody asked for a sign-in link for the address and never used it.
        let ghost = users.find_or_create_by_email(&email(NEW)).await.unwrap();
        let soon = Utc::now() + Duration::minutes(15);
        let link = NewMagicLink::new(ghost.id, &ghost.email, "ghost", "c", soon);
        users.issue_magic_link(link).await.unwrap();

        let code = f.ask(NEW).await;
        assert_eq!(
            f.mail.sent()[0].subject.len(),
            "Your OpsAgent email change code: 123456".len()
        );
        f.confirm().run(f.user.id, &code).await.unwrap();
        assert_eq!(f.stored_email().await, NEW);
        // The unproven row is gone with its link; the address is the account's alone.
        assert!(users.get(ghost.id).await.unwrap().is_none());
        assert!(users
            .consume_magic_link("ghost", Utc::now())
            .await
            .unwrap()
            .is_none());
        let at_new = users.find_by_email(&email(NEW)).await.unwrap().unwrap();
        assert_eq!(at_new.id, f.user.id);
    }

    /// The link is asked for at the old address while the change is being confirmed, so it is
    /// stored after the change removed the user's unspent links.
    #[tokio::test]
    async fn a_sign_in_link_or_code_for_the_old_address_no_longer_signs_in() {
        let f = fixture().await;
        let code = f.ask(NEW).await;
        f.confirm().run(f.user.id, &code).await.unwrap();
        let users: &dyn UsersRepo = &f.store;
        let (token, soon) = ("late-link", Utc::now() + Duration::minutes(15));
        let token_hash = hash_token(token);
        let late = code_hash(SECRET, &token_hash, "123456");
        let link = NewMagicLink::new(f.user.id, &f.user.email, &token_hash, &late, soon);
        users.issue_magic_link(link).await.unwrap();

        let redeem = RedeemMagicLink::new(Arc::new(f.store.clone()), Arc::new(SystemClock));
        let err = redeem.run(token).await.unwrap_err();
        assert!(matches!(err, AppError::Gone("link_invalid")), "{err:?}");
        let verify = crate::actions::auth::VerifyCode::new(
            Arc::new(f.store.clone()),
            Arc::new(MemRateLimiter::default()),
            Arc::new(SystemClock),
            SECRET.into(),
        );
        let input = crate::actions::auth::VerifyCodeInput {
            email: OLD.into(),
            code: "123456".into(),
            client_ip: None,
        };
        assert_invalid(verify.run(input).await);
        assert!(!f
            .store
            .audit_entries()
            .iter()
            .any(|e| e.action == "auth.sign_in"));
    }

    #[tokio::test]
    async fn member_recipient_rows_follow_the_new_address() {
        use opsagent_core::org::{NewOrganisation, OrganisationsRepo, Role};
        use opsagent_deliver::repo::{NewRecipient, RecipientsRepo};
        let f = fixture().await;
        let orgs: &dyn OrganisationsRepo = &f.store;
        let new_org = NewOrganisation {
            id: Uuid::new_v4(),
            slug: "acme".into(),
            name: "Acme".into(),
            timezone: "UTC".into(),
            kek_version: 1,
            wrapped_dek: vec![1],
            signup_source: None,
        };
        let org = orgs.insert(new_org).await.unwrap().id;
        let member = orgs.add_member(org, f.user.id, Role::Owner).await.unwrap();
        let recipients: &dyn RecipientsRepo = &f.store;
        let row = |address: &str, member_id| NewRecipient {
            connection_id: None,
            email: address.into(),
            member_id,
            confirm: None,
        };
        let mine = recipients
            .insert(org, row(OLD, Some(member.id)))
            .await
            .unwrap();
        let other = recipients
            .insert(org, row("ext@example.com", None))
            .await
            .unwrap();

        let code = f.ask(NEW).await;
        f.confirm().run(f.user.id, &code).await.unwrap();
        let sent_to = recipients.for_connection(org, None).await.unwrap();
        let mut ids: Vec<_> = sent_to.iter().map(|r| (r.id, r.email.as_str())).collect();
        ids.sort();
        let mut want = vec![(mine.id, NEW), (other.id, "ext@example.com")];
        want.sort();
        assert_eq!(ids, want);
    }

    #[tokio::test]
    async fn an_account_erased_before_the_code_is_entered_changes_and_tells_nothing() {
        let f = fixture().await;
        let code = f.ask(NEW).await;
        let users: &dyn UsersRepo = &f.store;
        let gone = users.set_email(Uuid::new_v4(), &email(NEW)).await;
        assert!(matches!(gone, Err(RepoError::NotFound)), "{gone:?}");
        users.erase(f.user.id, Utc::now()).await.unwrap();
        let err = f.confirm().run(f.user.id, &code).await.unwrap_err();
        assert!(
            matches!(
                err,
                AppError::Gone("code_invalid") | AppError::Unauthenticated
            ),
            "{err:?}"
        );
        assert!(f.store.audit_entries().is_empty());
        assert_eq!(f.mail.sent().len(), 1, "no notice");
    }

    #[tokio::test]
    async fn an_address_taken_after_the_code_was_mailed_fails_cleanly() {
        let f = fixture().await;
        let code = f.ask(NEW).await;
        proven(&f.store, NEW).await;
        let err = f.confirm().run(f.user.id, &code).await.unwrap_err();
        assert!(
            matches!(
                err,
                AppError::Refused {
                    status: StatusCode::CONFLICT,
                    code: "email_taken",
                    ..
                }
            ),
            "{err:?}"
        );
        assert_eq!(f.stored_email().await, OLD);
        assert!(f.store.audit_entries().is_empty());
        assert_eq!(f.mail.sent().len(), 1, "no notice");
    }

    #[tokio::test]
    async fn the_current_an_unusable_or_a_closed_address_is_refused_without_mail() {
        let f = fixture_with(SignupAllowlist::parse("example.com")).await;
        let code = |r: AppResult<()>| match r {
            Err(AppError::Refused { status, code, .. }) => (status.as_u16(), code),
            Err(AppError::Invalid(_)) => (422, "validation"),
            other => panic!("{other:?}"),
        };
        let ask = |to: &'static str| f.request.run(f.user.id, to, None);
        assert_eq!(
            code(ask(" OLD@example.com ").await),
            (422, "email_unchanged")
        );
        assert_eq!(code(ask("not-an-email").await), (422, "validation"));
        assert_eq!(code(ask(NEW).await), (422, "email_not_allowed"));
        assert!(f.mail.sent().is_empty());
        let unknown = f.request.run(Uuid::new_v4(), "a@example.com", None).await;
        assert!(matches!(unknown, Err(AppError::Unauthenticated)));
        ask("fine@example.com").await.unwrap();
        assert_eq!(f.mail.sent().len(), 1);
    }

    #[tokio::test]
    async fn requests_share_the_sign_in_mail_caps_and_a_per_user_cap() {
        let f = fixture().await;
        // Five codes an hour per user, whatever the address.
        for n in 0..5 {
            f.ask(&format!("n{n}@new.example")).await;
        }
        let err = f.request.run(f.user.id, NEW, None).await.unwrap_err();
        assert!(matches!(err, AppError::RateLimited { .. }), "{err:?}");
        assert_eq!(f.mail.sent().len(), 5);

        // The address's sign-in mail budget counts: after five sign-in mails, no change code.
        let f = fixture().await;
        let limiter = Arc::new(MemRateLimiter::default());
        let caps = (limiter.clone() as Arc<dyn RateLimiter>, 1000);
        let sign_in = crate::actions::auth::RequestMagicLink::new(
            Arc::new(f.store.clone()),
            caps.clone(),
            f.mail.clone(),
            WEB.into(),
            Arc::new(SystemClock),
            SECRET.into(),
            SignupAllowlist::parse("nowhere.example"),
        );
        for _ in 0..5 {
            let input = crate::actions::auth::MagicLinkInput {
                email: NEW.into(),
                client_ip: None,
                return_to: None,
                name: None,
            };
            sign_in.run(input).await.unwrap();
        }
        let request = RequestEmailChange::new(
            Arc::new(f.store.clone()),
            caps,
            f.mail.clone(),
            Arc::new(SystemClock),
            SECRET.into(),
            SignupAllowlist::default(),
        );
        let err = request.run(f.user.id, NEW, None).await.unwrap_err();
        assert!(matches!(err, AppError::RateLimited { .. }), "{err:?}");
    }

    /// Decision 2026-11-11: providers are matched on their own id, never relinked by email.
    #[tokio::test]
    async fn google_and_github_still_sign_in_to_the_account_after_the_change() {
        let f = fixture().await;
        let users: &dyn UsersRepo = &f.store;
        let old = &f.user.email;
        users
            .find_or_create_google("sub-1", old, None, true, true)
            .await
            .unwrap();
        users
            .find_or_create_github(42, old, None, true)
            .await
            .unwrap();
        let code = f.ask(NEW).await;
        f.confirm().run(f.user.id, &code).await.unwrap();

        // The providers still report the old address.
        let google = SignInGoogle::new(Arc::new(f.store.clone()), Default::default());
        let profile = GoogleProfile {
            google_id: "sub-1".into(),
            email: old.clone(),
            name: None,
            hosted_domain: Some("example.com".into()),
        };
        assert_eq!(google.run(profile).await.unwrap(), f.user.id);
        let github = SignInGithub::new(Arc::new(f.store.clone()), Default::default());
        let profile = GithubProfile {
            github_id: 42,
            email: old.clone(),
            name: None,
        };
        assert_eq!(github.run(profile).await.unwrap(), f.user.id);

        // Same account, still at the new address, and no second account at the old one.
        let u = users.get(f.user.id).await.unwrap().unwrap();
        assert_eq!(u.email.as_str(), NEW);
        assert_eq!(
            (u.google_id.as_deref(), u.github_id),
            (Some("sub-1"), Some(42))
        );
        assert!(users.find_by_email(old).await.unwrap().is_none());
    }
}
