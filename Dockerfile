# syntax=docker/dockerfile:1
# Bases are pinned by digest; Dependabot (docker) bumps tag and digest together.
FROM rust:1.100-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea AS builder
WORKDIR /src
COPY . .
# No BuildKit cache mounts: Railway requires a per-service mount id, and api, worker and
# scheduler all build from this file.
RUN cargo build --release -p opsagent-brain --bin opsagent-brain \
    && cp target/release/opsagent-brain /opsagent-brain

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
# A shell is needed: Railway runs the pre-deploy command through one.
# `upgrade`: take the security fixes Debian has shipped since the pinned base was built.
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates tzdata libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home opsagent
COPY --from=builder /opsagent-brain /usr/local/bin/opsagent-brain
WORKDIR /app
COPY templates ./templates
# The AWS RDS CA bundle, so DATABASE_URL can carry
# `?sslmode=verify-full&sslrootcert=/etc/ssl/rds/global-bundle.pem` (see deploy/README.md).
COPY deploy/backup/rds-global-bundle.pem /etc/ssl/rds/global-bundle.pem
USER opsagent
ENV APP_ENV=production PORT=3000
EXPOSE 3000
CMD ["opsagent-brain", "start"]
