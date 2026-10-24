#!/usr/bin/env bash
# Tenancy lint (engineering principles, "Tenancy at the repository layer"): every raw SQL
# statement and every SeaORM query builder call against a tenant table in app/src must name
# organisation_id. A query that is deliberately cross-tenant (a worker loading its run by id,
# the scheduler's global pass) carries a `// tenancy: <reason>` comment on one of the three
# lines above it. Tenant tables are those with an organisation_id column.
# Self-test: delete `organisation_id` from the posture query in
# app/src/adapters/db/findings/mod.rs, run this (expect exit 1), then revert.
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 - "$@" <<'PY'
import pathlib, re, sys

# email_suppressions mixes global rows (unsubscribes, organisation_id NULL) and per-organisation
# rows (ignored); its queries must still name organisation_id, as the NULL-or-org filter does.
TENANT = ["audit_events", "connections", "deliveries", "email_suppressions", "findings", "integrations",
          "invites", "members", "oauth_access_tokens", "oauth_grants", "oauth_refresh_tokens", "recipients",
          "resources", "runs", "schedules"]
tables = "|".join(TENANT)
raw = re.compile(rf"\b(?:FROM|UPDATE|INTO|JOIN)\s+({tables})\b", re.I)
builder = re.compile(rf"\b({tables})::Entity::(find|find_by_id|update_many|delete_many|delete_by_id)\b")
literal = re.compile(r'"(?:[^"\\]|\\.)*"', re.S)
allowed = re.compile(r"//\s*tenancy:\s*\S")

def exempt(lines, line_no):
    return any(allowed.search(l) for l in lines[max(0, line_no - 4):line_no - 1])

bad = []
for path in sorted(pathlib.Path("app/src").rglob("*.rs")):
    if "_entities" in path.parts:
        continue
    text = path.read_text()
    lines = text.split("\n")
    for m in literal.finditer(text):
        sql = m.group(0)
        hit = raw.search(sql)
        line_no = text.count("\n", 0, m.start()) + 1
        if hit and "organisation_id" not in sql and not exempt(lines, line_no):
            bad.append(f"{path}:{line_no}: raw SQL on {hit.group(1)} without organisation_id")
    for m in builder.finditer(text):
        stmt = text[m.start(): text.find(";", m.end()) + 1 or len(text)]
        line_no = text.count("\n", 0, m.start()) + 1
        if "OrganisationId" not in stmt and not exempt(lines, line_no):
            bad.append(f"{path}:{line_no}: {m.group(1)}::Entity::{m.group(2)} without OrganisationId")

for b in bad:
    print(b, file=sys.stderr)
if bad:
    print(f"tenancy lint: {len(bad)} unscoped quer{'y' if len(bad) == 1 else 'ies'}; add organisation_id or a `// tenancy: <reason>` comment", file=sys.stderr)
    sys.exit(1)
print("tenancy ok")
PY
