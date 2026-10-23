//! `start --server-and-worker`: the API's port is bound before the runner dequeues anything.
use std::time::Duration;

use opsagent_brain::{adapters::db::ledger_storage::stmt, cli};
use opsagent_ledger::JobKind;
use sea_orm::ConnectionTrait;
use serial_test::serial;

use super::runner::{enqueue, new_run};
use crate::support::TestApp;

#[tokio::test]
#[serial]
async fn server_and_worker_on_a_bound_port_fails_before_dequeuing() {
    let ctx = TestApp::boot().await;
    let run = new_run(&ctx, 1).await;
    enqueue(&ctx, JobKind::Verify, run).await;
    // A host name, as in the dev config; the port is taken on both loopback families.
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port();
    let _taken_v6 = std::net::TcpListener::bind(("::1", port)).ok();
    let mut c = ctx.state.config.clone();
    c.binding = "localhost".into();
    c.port = port;
    let started = cli::start_with(c, false, true, std::future::pending());
    let out = tokio::time::timeout(Duration::from_secs(30), started).await;
    assert!(out.expect("bounded").is_err());
    let row = ctx
        .db
        .query_one_raw(stmt(
            "SELECT count(*) n FROM jobs WHERE locked_at IS NULL AND attempts = 0",
            vec![],
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        row.try_get::<i64>("", "n").unwrap(),
        1,
        "the job was dequeued"
    );
}
