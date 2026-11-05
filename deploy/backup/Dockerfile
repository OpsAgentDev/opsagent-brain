# pg_dump refuses to dump a server newer than itself, so this base image must track
# or lead the Railway Postgres major (currently 18). Bump it with Postgres.
FROM postgres:18-alpine
RUN apk add --no-cache aws-cli bash
COPY deploy/backup/pg_dump.sh /usr/local/bin/pg_dump.sh
USER postgres
ENTRYPOINT ["/usr/local/bin/pg_dump.sh"]
