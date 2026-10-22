FROM postgres:17-alpine
RUN apk add --no-cache aws-cli bash
COPY deploy/backup/pg_dump.sh /usr/local/bin/pg_dump.sh
USER postgres
ENTRYPOINT ["/usr/local/bin/pg_dump.sh"]
