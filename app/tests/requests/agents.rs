use axum_test::TestServer;
use chrono::Utc;
use opsagent_brain::models::_entities::audit_events;
use opsagent_core::oauth::Grant;
use sea_orm::entity::prelude::*;
use serde_json::{json, Value};
use serial_test::serial;

use super::{oauth_authorize::*, support::*};

struct Team {
    slug: String,
    owner_csrf: String,
    /// Grants held by the owner and by the member.
    owner_grant: Uuid,
    mate_grant: Uuid,
    mate_member: String,
    mail: std::sync::Arc<opsagent_brain::mailers::CaptureMailer>,
}

async fn grant(app: &TestApp, org: Uuid, member: Uuid) -> Uuid {
    let g = Grant {
        id: Uuid::new_v4(),
        client_id: CLIENT.into(),
        member_id: member,
        organisation_id: org,
        created_at: Utc::now(),
        last_used_at: None,
        revoked_at: None,
    };
    app.state.uow.oauth().insert_grant(&g).await.unwrap();
    g.id
}

/// An owner and a member, each holding one grant; the session is the owner's.
async fn team(req: &mut TestServer, app: &TestApp) -> Team {
    let mail = prepare(app);
    let owner_csrf = sign_in(req, &mail, "owner@example.com").await;
    let org = create_org(req, &owner_csrf, "Team").await;
    let slug = slug(&org);
    let res = req
        .post(&format!("/v1/orgs/{slug}/invites"))
        .add_header("X-CSRF-Token", &owner_csrf)
        .json(&json!({"email": "mate@example.com", "role": "member"}))
        .await;
    assert_eq!(res.status_code(), 201, "{}", res.text());
    let accept = format!("/v1/invites/{}/accept", token_of(&last_link(&mail)));
    req.clear_cookies();
    let tm = sign_in(req, &mail, "mate@example.com").await;
    assert_eq!(
        req.post(&accept)
            .add_header("X-CSRF-Token", &tm)
            .await
            .status_code(),
        200
    );
    req.clear_cookies();
    let owner_csrf = sign_in(req, &mail, "owner@example.com").await;
    client(app).await;
    let members = req
        .get(&format!("/v1/orgs/{slug}/members"))
        .await
        .json::<Vec<Value>>();
    let id = |email: &str| {
        let m = members.iter().find(|m| m["email"] == email).unwrap();
        m["id"].as_str().unwrap().to_owned()
    };
    let org_id: Uuid = org["id"].as_str().unwrap().parse().unwrap();
    let (mate_member, owner_member) = (id("mate@example.com"), id("owner@example.com"));
    Team {
        owner_grant: grant(app, org_id, owner_member.parse().unwrap()).await,
        mate_grant: grant(app, org_id, mate_member.parse().unwrap()).await,
        slug,
        owner_csrf,
        mate_member,
        mail,
    }
}

async fn as_mate(req: &mut TestServer, t: &Team) -> String {
    req.clear_cookies();
    sign_in(req, &t.mail, "mate@example.com").await
}

async fn revoked(app: &TestApp, org: Uuid, id: Uuid) -> bool {
    let g = app.state.uow.oauth().grant(org, id).await.unwrap().unwrap();
    g.revoked_at.is_some()
}

async fn org_id(req: &TestServer, slug: &str) -> Uuid {
    let orgs = req.get("/v1/orgs").await.json::<Vec<Value>>();
    let o = orgs.iter().find(|o| o["slug"] == slug).unwrap();
    o["id"].as_str().unwrap().parse().unwrap()
}

#[tokio::test]
#[serial]
async fn remove_member_revokes_their_grants() {
    serve(|mut req, app| async move {
        let t = team(&mut req, &app).await;
        let org = org_id(&req, &t.slug).await;
        let res = req
            .delete(&format!("/v1/orgs/{}/members/{}", t.slug, t.mate_member))
            .add_header("X-CSRF-Token", &t.owner_csrf)
            .await;
        assert_eq!(res.status_code(), 204);
        assert!(revoked(&app, org, t.mate_grant).await);
        assert!(!revoked(&app, org, t.owner_grant).await);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn delete_org_revokes_all_grants() {
    serve(|mut req, app| async move {
        let t = team(&mut req, &app).await;
        let org = org_id(&req, &t.slug).await;
        let res = req
            .delete(&format!("/v1/orgs/{}", t.slug))
            .add_header("X-CSRF-Token", &t.owner_csrf)
            .await;
        assert_eq!(res.status_code(), 204, "{}", res.text());
        assert!(revoked(&app, org, t.mate_grant).await);
        assert!(revoked(&app, org, t.owner_grant).await);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn owner_lists_all_member_lists_own() {
    serve(|mut req, app| async move {
        let t = team(&mut req, &app).await;
        let res = req.get(&format!("/v1/orgs/{}/agents", t.slug)).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        let all = res.json::<Vec<Value>>();
        let mut emails: Vec<_> = all
            .iter()
            .map(|a| a["member_email"].as_str().unwrap())
            .collect();
        emails.sort_unstable();
        assert_eq!(emails, ["mate@example.com", "owner@example.com"]);
        assert_eq!(all[0]["client_name"], "Demo client");
        assert_eq!(all[0]["client_kind"], "dynamic");
        assert_eq!(all[0]["last_used_at"], Value::Null);

        as_mate(&mut req, &t).await;
        let own = req
            .get(&format!("/v1/orgs/{}/agents", t.slug))
            .await
            .json::<Vec<Value>>();
        assert_eq!(own.len(), 1);
        assert_eq!(own[0]["grant_id"], t.mate_grant.to_string());
    })
    .await;
}

#[tokio::test]
#[serial]
async fn member_cannot_revoke_others_grant() {
    serve(|mut req, app| async move {
        let t = team(&mut req, &app).await;
        let org = org_id(&req, &t.slug).await;
        let csrf = as_mate(&mut req, &t).await;
        let url = |g: Uuid| format!("/v1/orgs/{}/agents/{g}", t.slug);
        let res = req
            .delete(&url(t.owner_grant))
            .add_header("X-CSRF-Token", &csrf)
            .await;
        assert_eq!(res.status_code(), 404);
        assert!(!revoked(&app, org, t.owner_grant).await);
        let res = req
            .delete(&url(t.mate_grant))
            .add_header("X-CSRF-Token", &csrf)
            .await;
        assert_eq!(res.status_code(), 204);
        assert!(revoked(&app, org, t.mate_grant).await);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn revoke_is_audited() {
    serve(|mut req, app| async move {
        let t = team(&mut req, &app).await;
        let res = req
            .delete(&format!("/v1/orgs/{}/agents/{}", t.slug, t.mate_grant))
            .add_header("X-CSRF-Token", &t.owner_csrf)
            .await;
        assert_eq!(res.status_code(), 204);
        let rows = audit_events::Entity::find()
            .filter(audit_events::Column::Action.eq("oauth.grant.revoked"))
            .all(&app.db)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].target_id.as_deref(),
            Some(t.mate_grant.to_string().as_str())
        );
        // Gone from the list.
        let left = req.get(&format!("/v1/orgs/{}/agents", t.slug)).await;
        assert_eq!(left.json::<Vec<Value>>().len(), 1);
    })
    .await;
}
