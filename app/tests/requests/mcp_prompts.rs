//! Resources and prompts over MCP.
use chrono::Duration;
use serde_json::{json, Value};
use serial_test::serial;

use super::{
    mcp_auth::{member_of, mint, rpc},
    mcp_tools::{draft, seed, world},
    support::*,
};

async fn ok(res: axum_test::TestResponse) -> Value {
    assert_eq!(res.status_code(), 200, "{}", res.text());
    res.json()
}

#[tokio::test]
#[serial]
async fn resources_list_and_read_are_org_scoped() {
    serve(|req, app| async move {
        let (a, conn, csrf) = world(&req, &app, "res@example.com").await;
        seed(&app, a.org, conn, &[draft(conn, "no_mfa", "", "u", "x")]).await;
        let list = ok(rpc(&req, Some(&a.token), "resources/list", json!({})).await).await;
        let uris: Vec<_> = list["result"]["resources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["uri"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            uris,
            [
                "opsagent://scans/latest",
                "opsagent://inventory/latest",
                "opsagent://findings/open"
            ]
        );
        let read = |token: String, uri: &'static str| {
            let req = &req;
            async move {
                let res = rpc(req, Some(&token), "resources/read", json!({"uri": uri})).await;
                let body = ok(res).await;
                let text = body["result"]["contents"][0]["text"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                serde_json::from_str::<Value>(&text).unwrap()
            }
        };
        let open = read(a.token.clone(), "opsagent://findings/open").await;
        assert_eq!(open["items"].as_array().unwrap().len(), 1, "{open}");
        let scans = read(a.token.clone(), "opsagent://scans/latest").await;
        assert!(scans["items"].is_array());
        let other = create_org(&req, &csrf, "Beta").await;
        let other = other["id"].as_str().unwrap().parse().unwrap();
        let m = member_of(&app, other).await;
        let (_, token) = mint(&app, other, m, Duration::hours(1)).await;
        for uri in ["opsagent://findings/open", "opsagent://inventory/latest"] {
            assert_eq!(read(token.clone(), uri).await["items"], json!([]), "{uri}");
        }
        let bad = rpc(
            &req,
            Some(&a.token),
            "resources/read",
            json!({"uri": "opsagent://nope"}),
        )
        .await;
        assert!(ok(bad).await["error"].is_object());
    })
    .await;
}

#[tokio::test]
#[serial]
async fn prompts_list_has_three() {
    serve(|req, app| async move {
        let (a, _, _) = world(&req, &app, "pl@example.com").await;
        let list = ok(rpc(&req, Some(&a.token), "prompts/list", json!({})).await).await;
        let names: Vec<_> = list["result"]["prompts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "triage_overnight_findings",
                "weekly_posture_summary",
                "fix_finding"
            ]
        );
        let fix = &list["result"]["prompts"][2];
        assert_eq!(fix["arguments"][0]["name"], "finding_id");
        assert_eq!(fix["arguments"][0]["required"], true);
    })
    .await;
}

async fn prompt(req: &axum_test::TestServer, token: &str, name: &str, args: Value) -> Value {
    let res = rpc(
        req,
        Some(token),
        "prompts/get",
        json!({"name": name, "arguments": args}),
    )
    .await;
    ok(res).await
}

#[tokio::test]
#[serial]
async fn fix_finding_says_do_not_apply() {
    serve(|req, app| async move {
        let (a, conn, _) = world(&req, &app, "fix@example.com").await;
        let evidence = "TOP-SECRET-EXCERPT";
        seed(
            &app,
            a.org,
            conn,
            &[draft(conn, "no_mfa", "", "u", evidence)],
        )
        .await;
        let found = rpc(
            &req,
            Some(&a.token),
            "tools/call",
            json!({"name": "list_findings", "arguments": {}}),
        )
        .await;
        let id = ok(found).await["result"]["structuredContent"]["items"][0]["id"].clone();
        let got = prompt(&req, &a.token, "fix_finding", json!({"finding_id": id})).await;
        let m = &got["result"]["messages"][0];
        assert_eq!(m["role"], "user", "{got}");
        let text = m["content"]["text"].as_str().unwrap();
        for phrase in ["propose", "for human review", "do not apply", "get_finding"] {
            assert!(text.contains(phrase), "{phrase}: {text}");
        }
        assert!(!text.contains(evidence));
        for name in ["triage_overnight_findings", "weekly_posture_summary"] {
            let got = prompt(&req, &a.token, name, json!({"connection": conn})).await;
            assert!(got["result"]["messages"][0]["content"]["text"]
                .as_str()
                .unwrap()
                .contains(&conn.to_string()));
        }
    })
    .await;
}

#[tokio::test]
#[serial]
async fn prompt_with_unknown_finding_is_not_found() {
    serve(|req, app| async move {
        let (a, _, _) = world(&req, &app, "nf@example.com").await;
        let id = uuid::Uuid::new_v4().to_string();
        let got = prompt(&req, &a.token, "fix_finding", json!({"finding_id": id})).await;
        assert_eq!(got["error"]["data"]["code"], "not_found", "{got}");
        let got = prompt(
            &req,
            &a.token,
            "triage_overnight_findings",
            json!({"connection": id}),
        )
        .await;
        assert_eq!(got["error"]["data"]["code"], "not_found", "{got}");
        let got = prompt(&req, &a.token, "fix_finding", json!({})).await;
        assert_eq!(got["error"]["data"]["code"], "invalid", "{got}");
    })
    .await;
}
