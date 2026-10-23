#!/usr/bin/env bash
# Fails when the committed openapi.json differs from the document generated from the code.
# Regenerate with: (cd app && cargo run -- task openapi:dump)
# OPENAPI_GENERATED / OPENAPI_COMMITTED override the two files (the test suite uses them).
set -euo pipefail
cd "$(dirname "$0")/.."
committed="${OPENAPI_COMMITTED:-$PWD/openapi.json}"
generated="${OPENAPI_GENERATED:-}"
if [ -z "$generated" ]; then
  generated="$(mktemp)"
  trap 'rm -f "$generated"' EXIT
  # The app builds its KEK at boot; the dump needs any well-formed key (32 zero bytes).
  export OPSAGENT_KEK="${OPSAGENT_KEK:-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=}"
  (cd app && cargo run -q -p opsagent-brain -- task openapi:dump "path:$generated")
fi
if ! diff -u "$committed" "$generated"; then
  echo "openapi.json is stale: run 'cargo run -- task openapi:dump' in app/ and commit it" >&2
  exit 1
fi
echo "openapi.json is current"
