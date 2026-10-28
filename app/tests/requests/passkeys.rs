use opsagent_brain::models::_entities::{passkeys, users};
use sea_orm::{entity::prelude::*, Set};
use serde_json::{json, Value};
use serial_test::serial;
use webauthn_authenticator_rs::{softpasskey::SoftPasskey, WebauthnAuthenticator};
use webauthn_rs::prelude::{CreationChallengeResponse, Url};

use super::support::*;

/// The id of the user with `email`.
async fn user_id(ctx: &TestApp, email: &str) -> Uuid {
    users::Entity::find()
        .filter(users::Column::Email.eq(email))
        .one(&ctx.db)
        .await
        .unwrap()
        .unwrap()
        .id
}

/// A passkey row for `user_id`, inserted directly; its id.
async fn insert_passkey(ctx: &TestApp, user_id: Uuid, cred: &[u8]) -> Uuid {
    let id = Uuid::now_v7();
    passkeys::ActiveModel {
        id: Set(id),
        user_id: Set(user_id),
        credential_id: Set(cred.to_vec()),
        credential: Set(json!({})),
        name: Set("Laptop".into()),
        created_at: Set(chrono::Utc::now().into()),
        last_used_at: Set(None),
    }
    .insert(&ctx.db)
    .await
    .unwrap();
    id
}

#[tokio::test]
#[serial]
async fn register_start_needs_session() {
    serve(|req, _ctx| async move {
        let res = req.post("/v1/auth/passkeys/register/start").await;
        assert_eq!(res.status_code(), 401);
        assert_eq!(req.get("/v1/auth/passkeys").await.status_code(), 401);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn register_start_returns_options_for_signed_in_user() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        let csrf = sign_in(&req, &mail, "pk@example.com").await;
        // Mutating, so CSRF applies.
        let res = req.post("/v1/auth/passkeys/register/start").await;
        assert_eq!(res.status_code(), 403);
        let res = req
            .post("/v1/auth/passkeys/register/start")
            .add_header("X-CSRF-Token", &csrf)
            .await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        let opts = res.json::<Value>();
        assert_eq!(opts["publicKey"]["rp"]["id"], "localhost");
        assert_eq!(opts["publicKey"]["rp"]["name"], "OpsAgent");
        let sel = &opts["publicKey"]["authenticatorSelection"];
        assert_eq!(sel["residentKey"], "required");
        assert_eq!(sel["requireResidentKey"], true);
        assert_eq!(opts["publicKey"]["user"]["name"], "pk@example.com");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn me_reports_has_passkey_false_then_true() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        sign_in(&req, &mail, "has@example.com").await;
        let me = req.get("/v1/auth/me").await.json::<Value>();
        assert_eq!(me["has_passkey"], false);
        insert_passkey(&ctx, user_id(&ctx, "has@example.com").await, &[1, 2, 3]).await;
        let me = req.get("/v1/auth/me").await.json::<Value>();
        assert_eq!(me["has_passkey"], true);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn delete_other_users_passkey_is_404() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        sign_in(&req, &mail, "owner@example.com").await;
        let owner = user_id(&ctx, "owner@example.com").await;
        let theirs = insert_passkey(&ctx, owner, &[7]).await;
        sign_out(&req, &csrf(&req).await).await;
        let csrf = sign_in(&req, &mail, "other@example.com").await;
        let mine = insert_passkey(&ctx, user_id(&ctx, "other@example.com").await, &[8]).await;
        for path in [
            format!("/v1/auth/passkeys/{theirs}"),
            format!("/v1/auth/passkeys/{}", Uuid::now_v7()),
            "/v1/auth/passkeys/not-a-uuid".into(),
        ] {
            let res = req.delete(&path).add_header("X-CSRF-Token", &csrf).await;
            assert_eq!(res.status_code(), 404, "{path}");
        }
        assert!(passkeys::Entity::find_by_id(theirs)
            .one(&ctx.db)
            .await
            .unwrap()
            .is_some());
        let res = req
            .delete(&format!("/v1/auth/passkeys/{mine}"))
            .add_header("X-CSRF-Token", &csrf)
            .await;
        assert_eq!(res.status_code(), 204);
        assert_eq!(
            req.get("/v1/auth/passkeys").await.json::<Value>(),
            json!([])
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn register_and_list_with_soft_authenticator() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        let csrf = sign_in(&req, &mail, "soft@example.com").await;
        let start = req
            .post("/v1/auth/passkeys/register/start")
            .add_header("X-CSRF-Token", &csrf)
            .await;
        let mut ccr: CreationChallengeResponse = start.json();
        // SoftPasskey cannot make resident keys; real authenticators get `required` (checked
        // above). Finish does not depend on it, so the rest of the ceremony is still covered.
        let sel = ccr.public_key.authenticator_selection.as_mut().unwrap();
        (sel.resident_key, sel.require_resident_key) = (None, false);
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let credential = authenticator
            .do_registration(Url::parse(WEB_ORIGIN).unwrap(), ccr)
            .unwrap();
        let body = json!({ "credential": credential, "name": "Work laptop" });
        let res = req
            .post("/v1/auth/passkeys/register/finish")
            .add_header("X-CSRF-Token", &csrf)
            .json(&body)
            .await;
        assert_eq!(res.status_code(), 201, "{}", res.text());
        let view = res.json::<Value>();
        assert_eq!(view["name"], "Work laptop");
        assert!(view["last_used_at"].is_null());

        // The ceremony state is spent: a replay is refused.
        let res = req
            .post("/v1/auth/passkeys/register/finish")
            .add_header("X-CSRF-Token", &csrf)
            .json(&body)
            .await;
        assert_eq!(res.status_code(), 400);

        let list = req.get("/v1/auth/passkeys").await.json::<Value>();
        assert_eq!(list.as_array().unwrap().len(), 1);
        assert_eq!(list[0]["id"], view["id"]);
        assert_eq!(
            req.get("/v1/auth/me").await.json::<Value>()["has_passkey"],
            true
        );
    })
    .await;
}
