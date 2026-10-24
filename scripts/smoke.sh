#!/usr/bin/env bash
# Post-deploy smoke: /healthz and /readyz must return 200, MCP discovery answers and /mcp challenges; optionally verify one connection.
# Usage: scripts/smoke.sh BASE_URL (brain's own URL, e.g. https://brain.opsagent.dev)
# Optional env (all four, to run the verify step): SMOKE_ORG_SLUG (the org's URL slug),
# SMOKE_CONNECTION_ID, SMOKE_ROLE_ARN (the connection's verified read-role ARN) and
# SMOKE_SESSION_COOKIE (full "name=value" of a signed-in owner session). A service token
# replaces the cookie (and the CSRF fetch) once service tokens exist.
# Optional: SMOKE_BRIEFING_CONNECTION_ID (with SMOKE_ORG_SLUG and SMOKE_SESSION_COOKIE) checks the briefing preview; skipped otherwise.
# Exit: 0 ok, 1 health failed, 2 verify failed, 3 usage.
set -uo pipefail
[ $# -eq 1 ] || { echo "usage: $0 BASE_URL" >&2; exit 3; }
base="${1%/}"
org="${SMOKE_ORG_SLUG:-}" conn="${SMOKE_CONNECTION_ID:-}" role="${SMOKE_ROLE_ARN:-}" cookie="${SMOKE_SESSION_COOKIE:-}"
n=$(( ${#org} > 0 )); n=$(( n + (${#conn} > 0) + (${#role} > 0) + (${#cookie} > 0) ))
[ "$n" = 0 ] || [ "$n" = 4 ] || { echo "set all of SMOKE_ORG_SLUG, SMOKE_CONNECTION_ID, SMOKE_ROLE_ARN, SMOKE_SESSION_COOKIE or none" >&2; exit 3; }

for path in /healthz /readyz; do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$base$path") || true
  [ "$code" = 200 ] || { echo "FAIL $path -> ${code:-000}" >&2; exit 1; }
  echo "ok $path"
done
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$base/.well-known/oauth-protected-resource/mcp") || true
[ "$code" = 200 ] || { echo "FAIL MCP resource metadata -> ${code:-000}" >&2; exit 1; }
echo "ok MCP resource metadata"
hdr=$(curl -s -o /dev/null -D - --max-time 10 -X POST -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" --data '{}' "$base/mcp") || true
printf '%s' "$hdr" | head -1 | grep -q ' 401' && printf '%s' "$hdr" | grep -qi '^www-authenticate:.*resource_metadata=' \
  || { echo "FAIL unauthenticated /mcp did not answer 401 with resource_metadata" >&2; exit 1; }
echo "ok MCP 401 challenge"
bc="${SMOKE_BRIEFING_CONNECTION_ID:-}"
run_briefing=0; [ -n "$bc" ] && [ -n "$org" ] && [ -n "$cookie" ] && run_briefing=1
[ "$n" = 4 ] || [ "$run_briefing" = 1 ] || exit 0

api="$base/v1"
curlc() { curl -s --max-time 10 -H "Cookie: $cookie" "$@"; }
csrf=$(curlc "$api/auth/csrf" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[ -n "$csrf" ] || { echo "FAIL could not fetch CSRF token (bad session cookie?)" >&2; exit 2; }
if [ "$n" = 4 ]; then
  code=$(curlc -o /dev/null -w '%{http_code}' -X POST -H "X-CSRF-Token: $csrf" \
    -H "Content-Type: application/json" --data "{\"role_arn\":\"$role\"}" \
    "$api/orgs/$org/connections/$conn/verify")
  [ "$code" = 202 ] || { echo "FAIL verify request -> $code" >&2; exit 2; }
  ok=0
  for _ in $(seq 1 60); do
    curlc "$api/orgs/$org/connections/$conn" | grep -q '"status":"connected"' && { ok=1; break; }
    sleep 2
  done
  [ "$ok" = 1 ] || { echo "FAIL connection not connected after 120s" >&2; exit 2; }
  echo "ok verify: connected"
fi
if [ "$run_briefing" = 1 ]; then
  code=$(curlc -o /dev/null -w '%{http_code}' -X POST -H "X-CSRF-Token: $csrf" \
    "$api/orgs/$org/connections/$bc/briefing/preview")
  [ "$code" = 200 ] || { echo "FAIL briefing preview -> $code" >&2; exit 2; }
  echo "ok briefing preview"
fi
exit 0
