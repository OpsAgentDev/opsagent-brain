# opsagent-brain
Rust (Loco.rs) backend for OpsAgent: API, workers and scheduler. Domain logic lives in `crates/*`, which must not depend on `loco-rs` or `sea-orm`.
Run locally: `docker compose up -d postgres redis`, create the `opsagent_brain_development` and `opsagent_brain_test` databases, then `cargo run -- start`. Tests: `cargo test --workspace`.
Check: `curl localhost:5150/healthz`; `/readyz` returns 200 only when Postgres and Redis answer.
