# opsagent-brain
Rust (Loco.rs) backend for OpsAgent: API, workers and scheduler. Domain logic lives in `crates/*`, which must not depend on `loco-rs` or `sea-orm`.
Run locally: `docker compose up -d postgres redis`, create the `opsagent_brain_development` and `opsagent_brain_test` databases, then `cargo run -- start`. Tests: `cargo test --workspace`.
Full stack in containers: `docker compose --profile brain up -d --build` (api :3000, worker, scheduler; env in `.env.docker.example`), then `scripts/smoke.sh http://localhost:3000`. Deployment: `deploy/README.md`.
Check: `curl localhost:5150/healthz`; `/readyz` returns 200 only when Postgres and Redis answer.
Auth env (see `app/config/*.yaml` `settings:`): `SESSION_SECRET` (required in production), `WEB_BASE_URL`, `APP_BASE_URL`, `COOKIE_SECURE`, `COOKIE_DOMAIN`, `GITHUB_CLIENT_ID`/`GITHUB_CLIENT_SECRET`, `MAILER_SMTP_URL` (e.g. `smtp://localhost:1025` for the compose `mailpit`, UI on :8025; takes precedence), `RESEND_API_KEY` (with neither set locally, magic links are logged, not sent), `OPSAGENT_KEK` (base64, 32 bytes; needed to create orgs).
