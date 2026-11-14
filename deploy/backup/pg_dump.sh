#!/usr/bin/env bash
# Nightly logical backup: pg_dump (custom format) of $DATABASE_URL, uploaded to $BACKUP_BUCKET.
# Needs pg_dump and the AWS CLI. BACKUP_ENDPOINT_URL targets an S3-compatible store (Cloudflare R2).
# Retention (30 days) is a bucket lifecycle rule on $BACKUP_BUCKET, not done here.
set -euo pipefail
: "${DATABASE_URL:?}" "${BACKUP_BUCKET:?}"
file="opsagent-$(date -u +%Y%m%dT%H%M%SZ).dump"
trap 'rm -f "/tmp/$file"' EXIT
# Split DATABASE_URL into libpq env vars so the password never appears in argv.
# shortcut: expects postgres://user:pass@host[:port]/db[?sslmode=..&sslrootcert=..] with no percent-encoding; extend if the URL changes.
rest="${DATABASE_URL#*://}"; creds="${rest%%@*}"; hostdb="${rest#*@}"; hostport="${hostdb%%/*}"
db="${hostdb#*/}"; query=""; [[ $db == *\?* ]] && query="${db#*\?}"
export PGUSER="${creds%%:*}" PGPASSWORD="${creds#*:}" PGHOST="${hostport%%:*}" PGDATABASE="${db%%\?*}"
[[ $hostport == *:* ]] && export PGPORT="${hostport##*:}"
# A parameter this script does not know stops the run: dropping one could silently skip TLS checks.
IFS='&' read -ra params <<<"$query"
for p in "${params[@]}"; do
  case "${p%%=*}" in
    sslmode) export PGSSLMODE="${p#*=}" ;;
    sslrootcert) export PGSSLROOTCERT="${p#*=}" ;;
    *) echo "unsupported DATABASE_URL parameter: ${p%%=*}" >&2; exit 1 ;;
  esac
done
pg_dump --format=custom --no-owner --file="/tmp/$file"
aws s3 cp "/tmp/$file" "s3://$BACKUP_BUCKET/postgres/$file" ${BACKUP_ENDPOINT_URL:+--endpoint-url "$BACKUP_ENDPOINT_URL"}
echo "uploaded s3://$BACKUP_BUCKET/postgres/$file"
