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
