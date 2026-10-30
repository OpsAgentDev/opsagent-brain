use chrono::{DateTime, Duration, Utc};
use opsagent_brain::actions::uow::Repos;
use opsagent_core::{
    model::MsgRole,
    org::Role,
    repo::{PageRequest, RepoError},
    retention::TtlTable,
    user::Email,
};
use uuid::Uuid;

use super::connections::org;
use super::contract_suite;

/// Whole seconds from one base instant, so instants survive Postgres' microsecond timestamps
/// unchanged and two calls of `t(n)` agree even when a second boundary passes between them.
fn t(secs: i64) -> DateTime<Utc> {
    static BASE: std::sync::LazyLock<i64> = std::sync::LazyLock::new(|| Utc::now().timestamp());
    DateTime::from_timestamp(*BASE + secs, 0).unwrap()
}

/// A new user's membership of `o`.
async fn member(s: &dyn Repos, o: Uuid) -> Uuid {
    let email = Email::parse(&format!("{}@example.com", Uuid::now_v7())).unwrap();
    let user = s.users().find_or_create_by_email(&email).await.unwrap();
    s.orgs()
        .add_member(o, user.id, Role::Member)
        .await
        .unwrap()
        .id
}

fn page(limit: u64) -> PageRequest {
    PageRequest { after: None, limit }
}

contract_suite! {
    async fn chat_session_visible_only_to_its_member(s) {
        let (o, other) = (org(s).await, org(s).await);
        let (alice, bob) = (member(s, o).await, member(s, o).await);
        let chat = s.chat();
        let a1 = chat.create_session(o, alice, "costs", t(-30)).await.unwrap();
        assert_eq!((a1.organisation_id, a1.member_id, a1.title.as_str()), (o, alice, "costs"));
        assert_eq!((a1.created_at, a1.last_message_at), (t(-30), t(-30)));
        let a2 = chat.create_session(o, alice, "iam", t(-20)).await.unwrap();
        chat.create_session(o, bob, "bob's", t(-10)).await.unwrap();
        assert_eq!(chat.session(o, alice, a1.id).await.unwrap().as_ref(), Some(&a1));
        assert_eq!(chat.session(o, bob, a1.id).await.unwrap(), None);
        assert_eq!(chat.session(other, alice, a1.id).await.unwrap(), None);
        // Newest message first; a message moves its session up.
        chat.append(o, a1.id, MsgRole::User, "hi", false, t(-5)).await.unwrap();
        let first = chat.sessions(o, alice, page(1)).await.unwrap();
        assert_eq!(first.items.iter().map(|x| x.id).collect::<Vec<_>>(), [a1.id]);
        assert_eq!(first.items[0].last_message_at, t(-5));
        let rest = PageRequest { after: first.next, limit: 1 };
        let rest = chat.sessions(o, alice, rest).await.unwrap();
        assert_eq!(rest.items.iter().map(|x| x.id).collect::<Vec<_>>(), [a2.id]);
        assert!(rest.next.is_none());
        assert!(chat.sessions(other, alice, page(10)).await.unwrap().items.is_empty());
        // A session of another organisation takes no messages.
        let wrong = chat.append(other, a1.id, MsgRole::User, "x", false, t(0)).await;
        assert!(matches!(wrong, Err(RepoError::NotFound)));
        assert!(chat.recent_messages(other, a1.id, 10).await.unwrap().is_empty());
    }

    async fn recent_messages_returns_last_n_oldest_first(s) {
        let o = org(s).await;
        let m = member(s, o).await;
        let chat = s.chat();
        let id = chat.create_session(o, m, "t", t(-100)).await.unwrap().id;
        for i in 0..5 {
            let role = if i % 2 == 0 { MsgRole::User } else { MsgRole::Assistant };
            chat.append(o, id, role, &format!("m{i}"), i == 4, t(-50 + i)).await.unwrap();
        }
        let got = chat.recent_messages(o, id, 3).await.unwrap();
        let texts: Vec<_> = got.iter().map(|x| x.text.as_str()).collect();
        assert_eq!(texts, ["m2", "m3", "m4"]);
        assert_eq!(got[0].role, MsgRole::User);
        assert_eq!(got[1].role, MsgRole::Assistant);
        assert_eq!((got[2].partial, got[2].created_at, got[2].session_id), (true, t(-46), id));
        assert!(!got[0].partial);
        assert_eq!(chat.recent_messages(o, id, 20).await.unwrap().len(), 5);
    }

    async fn first_user_message_titles_an_untitled_session(s) {
        let o = org(s).await;
        let m = member(s, o).await;
        let chat = s.chat();
        let untitled = chat.create_session(o, m, "", t(-10)).await.unwrap().id;
        let titled = chat.create_session(o, m, "kept", t(-10)).await.unwrap().id;
        let long = "é".repeat(70);
        chat.append(o, untitled, MsgRole::Assistant, "not me", false, t(-9)).await.unwrap();
        chat.append(o, untitled, MsgRole::User, &long, false, t(-8)).await.unwrap();
        chat.append(o, untitled, MsgRole::User, "later", false, t(-7)).await.unwrap();
        chat.append(o, titled, MsgRole::User, "hi", false, t(-7)).await.unwrap();
        let title = |id| async move { chat.session(o, m, id).await.unwrap().unwrap().title };
        assert_eq!(title(untitled).await, "é".repeat(60));
        assert_eq!(title(titled).await, "kept");
    }

    async fn removing_member_deletes_their_sessions(s) {
        let o = org(s).await;
        let (gone, stays) = (member(s, o).await, member(s, o).await);
        let chat = s.chat();
        let theirs = chat.create_session(o, gone, "t", t(-10)).await.unwrap().id;
        chat.append(o, theirs, MsgRole::User, "hi", false, t(-9)).await.unwrap();
        let kept = chat.create_session(o, stays, "t", t(-10)).await.unwrap().id;
        assert!(s.orgs().remove_member(o, gone).await.unwrap());
        assert_eq!(chat.session(o, gone, theirs).await.unwrap(), None);
        assert!(chat.recent_messages(o, theirs, 10).await.unwrap().is_empty());
        assert!(chat.session(o, stays, kept).await.unwrap().is_some());
    }

    async fn ttl_deletes_chat_after_30_days_and_usage_after_13_months(s, seed) {
        let o = org(s).await;
        let m = member(s, o).await;
        let now = t(0);
        let chat = s.chat();
        let old = chat.create_session(o, m, "old", now - Duration::days(31)).await.unwrap().id;
        chat.append(o, old, MsgRole::User, "hi", false, now - Duration::days(31)).await.unwrap();
        let young = chat.create_session(o, m, "young", now - Duration::days(29)).await.unwrap().id;
        let r = s.retention();
        assert_eq!(r.delete_expired(TtlTable::ChatSessions, now - Duration::days(30), 100).await.unwrap(), 1);
        assert_eq!(chat.session(o, m, old).await.unwrap(), None);
        assert!(chat.recent_messages(o, old, 10).await.unwrap().is_empty());
        assert!(chat.session(o, m, young).await.unwrap().is_some());

        seed.expiring(o, TtlTable::AiUsage, now - Duration::days(396)).await;
        seed.expiring(o, TtlTable::AiUsage, now - Duration::days(394)).await;
        assert_eq!(r.delete_expired(TtlTable::AiUsage, now - Duration::days(395), 100).await.unwrap(), 1);
        assert_eq!(seed.expiring_left(TtlTable::AiUsage).await, 1);
    }
}
