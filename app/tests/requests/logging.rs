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
async fn request_logs_carry_route_template_not_secrets() {
    let buf = Buf::default();
    let sub = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
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
    assert!(out.contains("/v1/integrations/slack/callback"), "{out}");
    assert!(!out.contains("SECRETCODE"), "{out}");
    assert!(!out.contains("SECRETTOKEN"), "{out}");
}
