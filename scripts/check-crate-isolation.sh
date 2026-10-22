#!/usr/bin/env bash
# Domain crates under crates/ must not depend on loco-rs or sea-orm.
# Self-test: add `loco-rs = "1"` to crates/core/Cargo.toml, run this (expect exit 1), then revert.
set -u
cd "$(dirname "$0")/.."
if grep -nE 'loco-rs|sea-orm' crates/*/Cargo.toml; then
  echo "crate isolation violated: crates/* must not depend on loco-rs or sea-orm" >&2
  exit 1
fi
echo "crate isolation ok"
