#!/usr/bin/env bash
# Nightly logical backup: pg_dump (custom format) of $DATABASE_URL, uploaded to $BACKUP_BUCKET.
# Needs pg_dump and the AWS CLI. BACKUP_ENDPOINT_URL targets an S3-compatible store (Cloudflare R2).
# Retention (30 days) is a bucket lifecycle rule on $BACKUP_BUCKET, not done here.
set -euo pipefail
: "${DATABASE_URL:?}" "${BACKUP_BUCKET:?}"
file="opsagent-$(date -u +%Y%m%dT%H%M%SZ).dump"
trap 'rm -f "/tmp/$file"' EXIT
# Split DATABASE_URL into libpq env vars so the password never appears in argv.
# shortcut: expects postgres://user:pass@host[:port]/db with no percent-encoding or query string; extend if Railway's URL changes.
rest="${DATABASE_URL#*://}"; creds="${rest%%@*}"; hostdb="${rest#*@}"; hostport="${hostdb%%/*}"
export PGUSER="${creds%%:*}" PGPASSWORD="${creds#*:}" PGHOST="${hostport%%:*}" PGDATABASE="${hostdb#*/}"
[[ $hostport == *:* ]] && export PGPORT="${hostport##*:}"
pg_dump --format=custom --no-owner --file="/tmp/$file"
aws s3 cp "/tmp/$file" "s3://$BACKUP_BUCKET/postgres/$file" ${BACKUP_ENDPOINT_URL:+--endpoint-url "$BACKUP_ENDPOINT_URL"}
echo "uploaded s3://$BACKUP_BUCKET/postgres/$file"
