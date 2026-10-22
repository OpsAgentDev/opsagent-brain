#!/usr/bin/env bash
# Logging lint (ArchBoss docs/tech-spec/logging.md): `tracing` is the only facade. Fails on `log::`
# or `env_logger` in any .rs file outside tests/ directories and outside the trailing
# `#[cfg(test)]` module (everything from the first `#[cfg(test)]` line is treated as test code).
set -euo pipefail
cd "$(dirname "$0")/.."
bad=$(find app crates -name '*.rs' -not -path '*/tests/*' -not -path '*/target/*' -print0 |
  xargs -0 awk '/#\[cfg\(test\)\]/ { nextfile } /log::|env_logger/ { print FILENAME ":" FNR ": " $0 }')
if [ -n "$bad" ]; then echo "$bad" >&2; echo "check-logging: use tracing, not log/env_logger" >&2; exit 1; fi
echo "check-logging: ok"
