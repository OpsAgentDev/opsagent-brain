#!/usr/bin/env bash
# No Cargo.toml in the workspace may depend on loco; domain crates under crates/ must not depend
# on sea-orm either; and `cargo tree -i loco-rs` must not find the crate anywhere in the graph.
# Self-test: add `loco-rs = "1"` to crates/core/Cargo.toml, run this (expect exit 1), then revert.
set -u
cd "$(dirname "$0")/.."
fail=0
if grep -niE 'loco' Cargo.toml app/Cargo.toml app/migration/Cargo.toml crates/*/Cargo.toml; then
  echo "crate isolation violated: no Cargo.toml may depend on loco" >&2
  fail=1
fi
if grep -nE 'sea-orm' crates/*/Cargo.toml; then
  echo "crate isolation violated: crates/* must not depend on sea-orm" >&2
  fail=1
fi
# Passing case: `cargo tree -i` fails with "did not match any packages"; any other result fails.
if ! cargo tree --workspace -i loco-rs 2>&1 | grep -q 'did not match any packages'; then
  echo "crate isolation violated: loco-rs is in the dependency graph (or cargo tree failed)" >&2
  fail=1
fi
[ "$fail" -eq 0 ] || exit 1
echo "crate isolation ok"
