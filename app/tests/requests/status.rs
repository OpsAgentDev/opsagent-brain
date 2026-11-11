use sea_orm::ConnectionTrait;
use serde_json::Value;
use serial_test::serial;

use super::support::*;

#[tokio::test]
#[serial]
async fn status_is_public_and_counts_waiting_scans() {
    serve(|req, ctx| async move {
        ctx.db
            .execute_unprepared(
                "TRUNCATE jobs; INSERT INTO jobs (kind, args, run_at, max_attempts) VALUES \
                 ('scan', '{}', now() - interval '10 minutes', 3), \
                 ('scan', '{}', now() + interval '1 hour', 3)",
            )
            .await
            .unwrap();
        let res = req.get("/v1/status").await;
        assert_eq!(res.status_code(), 200);
        assert_eq!(
            res.headers().get("cache-control").unwrap(),
            "public, max-age=30"
        );
        let body: Value = res.json();
        assert_eq!(body["scans"]["waiting"], 1);
        let oldest = body["scans"]["oldest_wait_seconds"].as_i64().unwrap();
        assert!((590..=700).contains(&oldest), "{oldest}");
        assert!(body["deliveries"]["sent_24h"].as_i64().unwrap() >= 0);
        assert!(body["deliveries"]["failed_24h"].as_i64().unwrap() >= 0);
        ctx.db.execute_unprepared("TRUNCATE jobs").await.unwrap();
        let body: Value = req.get("/v1/status").await.json();
        assert_eq!(body["scans"]["waiting"], 0);
        assert_eq!(body["scans"]["oldest_wait_seconds"], 0);
    })
    .await;
}
