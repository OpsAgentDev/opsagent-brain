use serial_test::serial;

#[tokio::test]
#[serial]
async fn healthz_returns_ok() {
    crate::requests::support::serve(|request, _ctx| async move {
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
    crate::requests::support::serve(|request, _ctx| async move {
        let res = request.get("/readyz").await;
        assert_eq!(res.status_code(), 200);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn readyz_returns_503_when_redis_down() {
    // Port 1 is never listening; boot only needs Redis lazily, readyz must report 503.
    std::env::set_var("REDIS_URL", "redis://127.0.0.1:1");
    crate::requests::support::serve(|request, _ctx| async move {
        let res = request.get("/readyz").await;
        assert_eq!(res.status_code(), 503);
    })
    .await;
    std::env::remove_var("REDIS_URL");
}
