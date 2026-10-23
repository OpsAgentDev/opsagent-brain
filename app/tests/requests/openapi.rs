use std::process::Command;

use opsagent_brain::{adapters::db::Pg, controllers::openapi::document_json};
use opsagent_core::org::{OrganisationsRepo, Role};
use serde_json::Value;
use serial_test::serial;

use super::support::*;

const COMMITTED: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../openapi.json");
const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../scripts/openapi-diff.sh");

#[tokio::test]
#[serial]
async fn served_to_owners_only() {
    serve(|req, ctx| async move {
        let res = req.get("/openapi.json").await;
        assert_eq!(res.status_code(), 404, "anonymous");

        let mail = prepare(&ctx);
        let t = sign_in(&req, &mail, "owner@example.com").await;
        let org = create_org(&req, &t, "Acme").await;
        let org_id: uuid::Uuid = org["id"].as_str().unwrap().parse().unwrap();

        sign_out(&req, &t).await;
        let tm = sign_in(&req, &mail, "member@example.com").await;
        let me: Value = req.get("/v1/auth/me").await.json();
        let uid: uuid::Uuid = me["id"].as_str().unwrap().parse().unwrap();
        Pg::new(&ctx.db)
            .add_member(org_id, uid, Role::Member)
            .await
            .unwrap();
        let res = req.get("/openapi.json").await;
        assert_eq!(res.status_code(), 404, "plain member");

        sign_out(&req, &tm).await;
        sign_in(&req, &mail, "owner@example.com").await;
        let res = req.get("/openapi.json").await;
        assert_eq!(res.status_code(), 200);
        let doc: Value = res.json();
        assert_eq!(doc["info"]["title"], "OpsAgent brain");
        assert_eq!(doc["servers"][0]["url"], "https://brain.opsagent.dev/v1");
        for p in [
            "/orgs/{org}/findings",
            "/orgs/{org}/findings/{id}/accept",
            "/orgs/{org}/resources",
            "/orgs/{org}/runs/{id}",
            "/orgs/{org}/connections/{id}/scan",
            "/orgs/{org}/connections",
            "/orgs/{org}/members",
            "/auth/me",
        ] {
            assert!(doc["paths"][p].is_object(), "missing {p}");
        }
    })
    .await;
}

#[test]
fn committed_document_is_current() {
    let committed = std::fs::read_to_string(COMMITTED).expect("openapi.json is committed");
    assert_eq!(
        committed,
        document_json(),
        "run `cargo run -- task openapi:dump`"
    );
}

fn diff_script(committed: &str) -> bool {
    let dir = std::env::temp_dir().join(format!("openapi-diff-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let generated = dir.join("generated.json");
    std::fs::write(&generated, document_json()).unwrap();
    let committed_path = dir.join("committed.json");
    std::fs::write(&committed_path, committed).unwrap();
    let ok = Command::new("bash")
        .arg(SCRIPT)
        .env("OPENAPI_GENERATED", &generated)
        .env("OPENAPI_COMMITTED", &committed_path)
        .output()
        .unwrap()
        .status
        .success();
    std::fs::remove_dir_all(&dir).unwrap();
    ok
}

#[test]
fn diff_script_fails_on_drift() {
    let doc = document_json();
    assert!(diff_script(&doc), "identical documents pass");
    assert!(
        !diff_script(&doc.replace("OpsAgent brain", "Altered")),
        "drift fails"
    );
}
