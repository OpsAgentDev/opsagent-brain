# Build context is this directory (the Railway service root): `docker build deploy/backup`.
# pg_dump refuses to dump a server newer than itself, so this base image must track
# or lead the production Postgres major (currently 18). Bump it with Postgres.
# Pinned by digest; Dependabot (docker) bumps tag and digest together.
FROM postgres:18-alpine@sha256:1018733457011bf88d81db98cf43aac6d5150afc18787dbe204771fedf80ff95
# `upgrade`: take the security fixes Alpine has shipped since the pinned base was built.
# gosu (a Go binary the base image uses to drop root) is unused here, since this image starts as
# `postgres`, and it carries every High and Critical finding of the registry scan.
RUN apk upgrade --no-cache && apk add --no-cache aws-cli bash && rm /usr/local/bin/gosu
# The AWS RDS CA bundle (https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem), for
# `?sslmode=verify-full&sslrootcert=/etc/ssl/rds/global-bundle.pem` in DATABASE_URL.
COPY rds-global-bundle.pem /etc/ssl/rds/global-bundle.pem
COPY pg_dump.sh /usr/local/bin/pg_dump.sh
# The task runs with a read-only root; the dump is staged in /tmp, which gets a volume.
VOLUME ["/tmp"]
USER postgres
ENTRYPOINT ["/usr/local/bin/pg_dump.sh"]
