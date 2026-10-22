# AGENTS.md — opsagent-brain

This repo is **brain**: the Rust (Loco.rs) API, MCP server, workers, and scheduler for OpsAgent. It holds implementation only. All knowledge, decisions, specs, and plans live in the ArchBoss hub: `../OpsAgent-ArchBoss` (read its `AGENTS.md` first, then `DECISIONS.md`). If ArchBoss is not checked out beside this repo, stop and ask for it; do not reconstruct decisions from code.

No `CLAUDE.md` in this repo; this file is the only instruction file.

## Run
```
source "$HOME/.cargo/env"
docker compose up -d postgres redis mailpit        # ports 55432 / 56379 / 1025, 8025
export DATABASE_URL=postgres://loco:loco@localhost:55432/opsagent_brain_test
export REDIS_URL=redis://localhost:56379
export OPSAGENT_KEK=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=   # local only
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check
scripts/check-crate-isolation.sh && scripts/check-tenancy.sh && scripts/check-logging.sh && scripts/openapi-diff.sh
cargo run -- start --server-and-worker                 # API on :3000 (dev)
docker compose --profile brain up -d && scripts/smoke.sh http://localhost:3000
```

## Layout
- `app/` Loco shell: controllers (parse and respond), services (rules and transactions), models (SeaORM), workers, tasks, mailers.
- `crates/` Loco-free domain: `core`, `secrets`, `ledger`, `connectors`, `checks`. Never depend on `loco-rs` or `sea-orm` here.
- `templates/aws/` the customer-facing read-only role template, versioned with a checksum.
- `openapi.json` generated (`cargo loco task openapi:dump`), committed, diffed in CI.

## Rules (summary; the binding text is in ArchBoss `docs/tech-spec/engineering-principles.md`)
Ports and adapters, SOLID, DRY, YAGNI, explicit errors, functions ~50 lines, files ~400 lines, contract tests per trait, idempotent workers, tenant-scoped queries, no HTML served, no secrets in logs or audit metadata. The founder's commit-msg hook strips `Co-Authored-By`; do not bypass hooks.

## Logging
Binding spec: ArchBoss `docs/tech-spec/logging.md`. `tracing` only (structured fields); no `println!`/`eprintln!`/`dbg!`/`log::`. Clippy denies them workspace-wide and `scripts/check-logging.sh` bans `log::`/`env_logger` outside tests. Never log secrets, tokens, or provider error text.
