#!/usr/bin/env bash
# Post-deploy smoke: /healthz and /readyz must return 200; optionally verify one connection.
# Usage: scripts/smoke.sh BASE_URL
# Optional env (all three, to run the verify step): SMOKE_ORG_ID, SMOKE_CONNECTION_ID,
# SMOKE_SESSION_COOKIE (full "name=value" of a signed-in session). A service token replaces the
# cookie (and the CSRF fetch) once service tokens exist.
# Exit: 0 ok, 1 health failed, 2 verify failed, 3 usage.
set -uo pipefail
[ $# -eq 1 ] || { echo "usage: $0 BASE_URL" >&2; exit 3; }
base="${1%/}"
org="${SMOKE_ORG_ID:-}" conn="${SMOKE_CONNECTION_ID:-}" cookie="${SMOKE_SESSION_COOKIE:-}"
n=$(( ${#org} > 0 )); n=$(( n + (${#conn} > 0) + (${#cookie} > 0) ))
[ "$n" = 0 ] || [ "$n" = 3 ] || { echo "set all of SMOKE_ORG_ID, SMOKE_CONNECTION_ID, SMOKE_SESSION_COOKIE or none" >&2; exit 3; }

for path in /healthz /readyz; do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$base$path") || true
  [ "$code" = 200 ] || { echo "FAIL $path -> ${code:-000}" >&2; exit 1; }
  echo "ok $path"
done
[ "$n" = 3 ] || exit 0

api="$base/v1"
curlc() { curl -s --max-time 10 -H "Cookie: $cookie" "$@"; }
csrf=$(curlc "$api/auth/csrf" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[ -n "$csrf" ] || { echo "FAIL could not fetch CSRF token (bad session cookie?)" >&2; exit 2; }
code=$(curlc -o /dev/null -w '%{http_code}' -X POST -H "X-CSRF-Token: $csrf" \
  "$api/orgs/$org/connections/$conn/verify")
[ "$code" = 202 ] || { echo "FAIL verify request -> $code" >&2; exit 2; }
for _ in $(seq 1 60); do
  curlc "$api/orgs/$org/connections/$conn" | grep -q '"status":"connected"' && { echo "ok verify: connected"; exit 0; }
  sleep 2
done
echo "FAIL connection not connected after 120s" >&2
exit 2
