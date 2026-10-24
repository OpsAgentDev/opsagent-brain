use serial_test::serial;

/// The booted app resolves metadata documents through the real fetcher, which must refuse
/// non-public hosts before any request leaves the process.
#[tokio::test]
#[serial]
async fn private_hosts_are_not_fetched() {
    crate::requests::support::serve(|_, app| async move {
        for id in [
            "https://127.0.0.1/client.json",
            "https://localhost/client.json",
            "https://169.254.169.254/latest/meta-data",
            "https://[::1]/client.json",
            "http://example.com/client.json",
        ] {
            let e = app
                .state
                .actions
                .oauth
                .resolve_client
                .run(id, chrono::Utc::now())
                .await
                .unwrap_err();
            assert_eq!(e.error, "invalid_client", "{id}");
        }
    })
    .await;
}

#[tokio::test]
#[serial]
async fn dynamic_client_used_on_day_89_is_valid_on_day_120() {
    use chrono::{Duration, Utc};
    use opsagent_core::oauth::{ClientKind, OAuthClient};

    crate::requests::support::serve(|_, app| async move {
        let t0 = Utc::now();
        let client = OAuthClient {
            client_id: "dyn-slide".into(),
            kind: ClientKind::Dynamic,
            name: "D".into(),
            redirect_uris: vec!["https://a.example/cb".into()],
            document_fetched_at: None,
            document_cache_until: None,
            last_used_at: None,
            expires_at: Some(t0 + Duration::days(90)),
        };
        app.state.uow.oauth().upsert_client(&client).await.unwrap();
        let resolve = &app.state.actions.oauth.resolve_client;
        resolve
            .run("dyn-slide", t0 + Duration::days(89))
            .await
            .unwrap();
        resolve
            .run("dyn-slide", t0 + Duration::days(120))
            .await
            .unwrap();
        let e = resolve
            .run("dyn-slide", t0 + Duration::days(300))
            .await
            .unwrap_err();
        assert_eq!(e.error, "invalid_client");
    })
    .await;
}
