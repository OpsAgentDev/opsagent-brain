use loco_rs::testing::prelude::*;
use opsagent_brain::app::App;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn healthz_returns_ok() {
    request::<App, _, _>(|request, _ctx| async move {
        let res = request.get("/healthz").await;
        assert_eq!(res.status_code(), 200);
        assert_eq!(
            res.json::<serde_json::Value>(),
            serde_json::json!({"status": "ok"})
        );
    })
    .await;
}

#[tokio::test]
#[serial]
async fn readyz_returns_ok_when_deps_up() {
    request::<App, _, _>(|request, _ctx| async move {
        let res = request.get("/readyz").await;
        assert_eq!(res.status_code(), 200);
    })
    .await;
}
