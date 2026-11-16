# syntax=docker/dockerfile:1
# Bases are pinned by digest; Dependabot (docker) bumps tag and digest together.
FROM rust:1.100-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea AS builder
WORKDIR /src
COPY . .
# No BuildKit cache mounts: Railway requires a per-service mount id, and api, worker and
# scheduler all build from this file.
RUN cargo build --release -p opsagent-brain --bin opsagent-brain \
    && cp target/release/opsagent-brain /opsagent-brain

# Debian 13: the registry scan's High findings (util-linux, pam, zlib, glibc) have no fix in
# Debian 12. The binary is built on 12 and runs on the newer glibc and OpenSSL 3 here.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
# A shell is needed: Railway runs the pre-deploy command through one.
# `upgrade`: take the security fixes Debian has shipped since the pinned base was built.
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates tzdata libssl3t64 \
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
