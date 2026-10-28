use axum_test::TestServer;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use opsagent_brain::models::_entities::{passkeys, users};
use sea_orm::{entity::prelude::*, Set};
use serde_json::{json, Value};
use serial_test::serial;
use webauthn_authenticator_rs::{softpasskey::SoftPasskey, WebauthnAuthenticator};
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse, Url};

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
        let (_authenticator, body, view) = register(&req, &csrf).await;
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

type Soft = WebauthnAuthenticator<SoftPasskey>;

/// Registers a passkey named "Work laptop" with a software authenticator for the signed-in
/// session; the authenticator, the finish body and the created passkey.
async fn register(req: &TestServer, csrf: &str) -> (Soft, Value, Value) {
    let start = req
        .post("/v1/auth/passkeys/register/start")
        .add_header("X-CSRF-Token", csrf)
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
        .add_header("X-CSRF-Token", csrf)
        .json(&body)
        .await;
    assert_eq!(res.status_code(), 201, "{}", res.text());
    let view = res.json::<Value>();
    (authenticator, body, view)
}

async fn login_start(req: &TestServer, query: &str) -> axum_test::TestResponse {
    req.post(&format!("/v1/auth/passkeys/login/start{query}"))
        .add_header("Origin", WEB_ORIGIN)
        .await
}

async fn login_finish(req: &TestServer, credential: &Value) -> axum_test::TestResponse {
    req.post("/v1/auth/passkeys/login/finish")
        .add_header("Origin", WEB_ORIGIN)
        .json(&json!({ "credential": credential }))
        .await
}

/// The authenticator's assertion for the options `login/start` returned. SoftPasskey is not
/// discoverable: it needs the credential in the allow list and sends no user handle, so the
/// test does what a resident-key authenticator does itself (the handle is not signed).
fn assert_with(soft: &mut Soft, start: &Value, cred_id: &Value, user: Uuid) -> Value {
    let mut opts = start.clone();
    opts["publicKey"]["allowCredentials"] = json!([{ "type": "public-key", "id": cred_id }]);
    let rcr: RequestChallengeResponse = serde_json::from_value(opts).unwrap();
    let cred = soft
        .do_authentication(Url::parse(WEB_ORIGIN).unwrap(), rcr)
        .unwrap();
    let mut cred = serde_json::to_value(cred).unwrap();
    cred["response"]["userHandle"] = json!(B64.encode(user.as_bytes()));
    cred
}

const CONSENT: &str = "/oauth/consent?request_id=0192f3a4-7b1c-7d2e-8f3a-4b5c6d7e8f90";

#[tokio::test]
#[serial]
async fn passkey_login_start_checks_origin() {
    serve(|req, _ctx| async move {
        let res = req
            .post("/v1/auth/passkeys/login/start")
            .add_header("Origin", "https://evil.example")
            .await;
        assert_eq!(res.status_code(), 403);
        assert_eq!(res.json::<Value>()["code"], "bad_origin");
        let res = login_start(&req, "").await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        let opts = res.json::<Value>();
        assert!(opts["publicKey"]["challenge"].is_string());
        let allow = &opts["publicKey"]["allowCredentials"];
        assert!(allow.is_null() || allow == &json!([]), "{allow}");
        assert_eq!(opts["publicKey"]["userVerification"], "required");
        assert!(opts["mediation"].is_null());
    })
    .await;
}

#[tokio::test]
#[serial]
async fn passkey_login_finish_without_start_is_401() {
    serve(|req, _ctx| async move {
        let cred = json!({
            "id": "AQID", "rawId": "AQID", "type": "public-key", "extensions": {},
            "response": { "authenticatorData": "", "clientDataJSON": "", "signature": "" },
        });
        let res = login_finish(&req, &cred).await;
        assert_eq!(res.status_code(), 401, "{}", res.text());
        assert_eq!(res.json::<Value>()["code"], "passkey_invalid");
        let res = req
            .post("/v1/auth/passkeys/login/finish")
            .add_header("Origin", "https://evil.example")
            .json(&json!({ "credential": cred }))
            .await;
        assert_eq!(res.status_code(), 403);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn passkey_login_with_unknown_credential_is_401() {
    serve(|req, _ctx| async move {
        login_start(&req, "").await;
        let cred = json!({
            "id": "AQID", "rawId": "AQID", "type": "public-key", "extensions": {},
            "response": {
                "authenticatorData": "", "clientDataJSON": "", "signature": "",
                "userHandle": B64.encode(Uuid::now_v7().as_bytes()),
            },
        });
        let res = login_finish(&req, &cred).await;
        assert_eq!(res.status_code(), 401, "{}", res.text());
        assert_eq!(res.json::<Value>()["code"], "passkey_invalid");
        assert_eq!(req.get("/v1/auth/me").await.status_code(), 401);
    })
    .await;
}

/// Register, sign out, sign in with the passkey from a consent flow; then a replay and a
/// removed passkey are both 401.
#[tokio::test]
#[serial]
async fn passkey_login_keeps_return_to() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        let csrf = sign_in(&req, &mail, "login@example.com").await;
        let (mut soft, _, view) = register(&req, &csrf).await;
        let user = user_id(&ctx, "login@example.com").await;
        let row = passkeys::Entity::find()
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        let cred_id = json!(B64.encode(&row.credential_id));
        sign_out(&req, &csrf).await;

        let q = format!("?return_to={}", urlencoding::encode(CONSENT));
        let start = login_start(&req, &q).await.json::<Value>();
        let cred = assert_with(&mut soft, &start, &cred_id, user);
        let res = login_finish(&req, &cred).await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
        assert_eq!(
            res.json::<Value>()["redirect"],
            format!("{WEB_ORIGIN}{CONSENT}")
        );
        assert_eq!(
            req.get("/v1/auth/me").await.json::<Value>()["id"],
            json!(user)
        );
        let list = req.get("/v1/auth/passkeys").await.json::<Value>();
        assert!(list[0]["last_used_at"].is_string(), "{list}");

        // The ceremony state is spent: replaying the same assertion is refused.
        let res = login_finish(&req, &cred).await;
        assert_eq!(res.status_code(), 401);

        // A removed passkey no longer signs in, even with a fresh ceremony.
        let csrf = super::support::csrf(&req).await;
        let path = format!("/v1/auth/passkeys/{}", view["id"].as_str().unwrap());
        let res = req.delete(&path).add_header("X-CSRF-Token", &csrf).await;
        assert_eq!(res.status_code(), 204);
        sign_out(&req, &csrf).await;
        let start = login_start(&req, "").await.json::<Value>();
        let cred = assert_with(&mut soft, &start, &cred_id, user);
        let res = login_finish(&req, &cred).await;
        assert_eq!(res.status_code(), 401, "{}", res.text());
        assert_eq!(res.json::<Value>()["code"], "passkey_invalid");
    })
    .await;
}

/// A registered passkey whose assertion does not verify: a tampered signature, then a valid
/// signature over a different (earlier) challenge. Both 401 `passkey_invalid`, no session.
#[tokio::test]
#[serial]
async fn passkey_login_with_bad_signature_or_stale_challenge_is_401() {
    serve(|req, ctx| async move {
        let mail = prepare(&ctx);
        let csrf = sign_in(&req, &mail, "sig@example.com").await;
        let (mut soft, _, _) = register(&req, &csrf).await;
        let user = user_id(&ctx, "sig@example.com").await;
        let row = passkeys::Entity::find()
            .one(&ctx.db)
            .await
            .unwrap()
            .unwrap();
        let cred_id = json!(B64.encode(&row.credential_id));
        sign_out(&req, &csrf).await;

        let start = login_start(&req, "").await.json::<Value>();
        let mut cred = assert_with(&mut soft, &start, &cred_id, user);
        let mut sig = B64
            .decode(cred["response"]["signature"].as_str().unwrap())
            .unwrap();
        let last = sig.len() - 1;
        sig[last] ^= 0x01;
        cred["response"]["signature"] = json!(B64.encode(&sig));
        let res = login_finish(&req, &cred).await;
        assert_eq!(res.status_code(), 401, "{}", res.text());
        assert_eq!(res.json::<Value>()["code"], "passkey_invalid");

        let stale = login_start(&req, "").await.json::<Value>();
        let cred = assert_with(&mut soft, &stale, &cred_id, user);
        login_start(&req, "").await; // replaces the ceremony the assertion was made for
        let res = login_finish(&req, &cred).await;
        assert_eq!(res.status_code(), 401, "{}", res.text());
        assert_eq!(res.json::<Value>()["code"], "passkey_invalid");
        assert_eq!(req.get("/v1/auth/me").await.status_code(), 401);
    })
    .await;
}
