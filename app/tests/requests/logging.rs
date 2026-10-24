//! The request span names the route template, never the raw URI (OAuth codes, path tokens).
use std::sync::{Arc, Mutex};

use serial_test::serial;

use super::support::*;

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
#[serial]
async fn info_request_logs_carry_route_status_latency_not_secrets() {
    let buf = Buf::default();
    let sub = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .with_writer({
            let b = buf.clone();
            move || b.clone()
        })
        .finish();
    let _g = tracing::subscriber::set_default(sub);
    serve(|req, _ctx| async move {
        req.get("/v1/integrations/slack/callback?code=SECRETCODE&state=x")
            .await;
        req.post("/v1/unsubscribe/SECRETTOKEN").await;
    })
    .await;
    let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(out.contains("/v1/unsubscribe/{token}"), "{out}");
    // The INFO response event: status and latency.
    assert!(out.contains("status=410"), "{out}");
    assert!(out.contains("latency="), "{out}");
    assert!(out.contains("/v1/integrations/slack/callback"), "{out}");
    assert!(!out.contains("SECRETCODE"), "{out}");
    assert!(!out.contains("SECRETTOKEN"), "{out}");
}

#[tokio::test]
#[serial]
async fn timeout_response_is_logged_with_request_id() {
    let buf = Buf::default();
    let sub = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .with_writer({
            let b = buf.clone();
            move || b.clone()
        })
        .finish();
    let _g = tracing::subscriber::set_default(sub);
    serve_with(
        |c| c.request_timeout_secs = 1,
        |srv, _ctx| async move {
            let res = srv
                .get("/_test/slow")
                .add_header("x-request-id", "slow-log-1")
                .await;
            assert_eq!(res.status_code(), 504);
        },
    )
    .await;
    let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    let line = out
        .lines()
        .find(|l| l.contains("status=504"))
        .unwrap_or_else(|| panic!("{out}"));
    assert!(line.contains(r#"request_id="slow-log-1""#), "{line}");
    assert!(line.contains("/_test/slow"), "{line}");
}
