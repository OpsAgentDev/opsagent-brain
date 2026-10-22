#!/usr/bin/env bash
# Logging lint (ArchBoss docs/tech-spec/logging.md): `tracing` is the only facade.
# 1. Fails on `log::` or `env_logger` in any .rs file outside tests/ directories and outside a
#    `#[cfg(test)]` module. The cut-off applies only when `#[cfg(test)]` is followed by `mod ` on the
#    next non-blank line; everything after it in that file is treated as test code.
# 2. Fails if a workspace crate lists `log` or `env_logger` as a normal (non-dev) dependency.
#    Transitive `log` (via loco, tracing) is not ours to remove, so only direct deps count.
set -euo pipefail
cd "$(dirname "$0")/.."
bad=$(find app crates -name '*.rs' -not -path '*/tests/*' -not -path '*/target/*' -print0 |
  xargs -0 awk '
    pending { if ($0 ~ /^[[:space:]]*$/) next; if ($0 ~ /^[[:space:]]*(pub(\([a-z]+\))?[[:space:]]+)?mod[[:space:]]/) nextfile; pending = 0 }
    /^[[:space:]]*#\[cfg\(test\)\][[:space:]]*$/ { pending = 1; next }
    /log::|env_logger/ { print FILENAME ":" FNR ": " $0 }')
if [ -n "$bad" ]; then echo "$bad" >&2; echo "check-logging: use tracing, not log/env_logger" >&2; exit 1; fi
direct=$(cargo metadata --format-version 1 --no-deps | python3 -c '
import json, sys
for p in json.load(sys.stdin)["packages"]:
    for d in p["dependencies"]:
        if d["name"] in ("log", "env_logger") and d["kind"] in (None, "normal"):
            print(p["name"], "depends on", d["name"])')
if [ -n "$direct" ]; then echo "$direct" >&2; echo "check-logging: log/env_logger must not be a dependency" >&2; exit 1; fi
echo "check-logging: ok"
